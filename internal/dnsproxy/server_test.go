package dnsproxy

import (
	"context"
	"net"
	"testing"

	"github.com/miekg/dns"

	"github.com/moolen/nie/internal/config"
	"github.com/moolen/nie/internal/ebpf"
	"github.com/moolen/nie/internal/policy"
)

func TestServeDNS_EnforceDeniedHostReturnsRefused(t *testing.T) {
	srv := New(ServerConfig{
		Mode:   config.ModeEnforce,
		Policy: allowOnly("*.github.com"),
		Upstream: fakeUpstream(func(q string) *dns.Msg {
			t.Fatalf("upstream should not be called for %q", q)
			return nil
		}),
		Trust: noopTrustWriter{},
	})

	resp := exchangeLocal(t, srv, question("example.com."))
	if resp.Rcode != dns.RcodeRefused {
		t.Fatalf("Rcode = %d, want %d", resp.Rcode, dns.RcodeRefused)
	}
}

func TestServeDNS_AuditDeniedHostForwardsAndLearnsARecords(t *testing.T) {
	var learned []string
	srv := New(ServerConfig{
		Mode:     config.ModeAudit,
		Policy:   allowOnly("*.github.com"),
		Upstream: fakeUpstreamAnswer("example.com.", "203.0.113.10", 60),
		Trust:    captureTrustWriter(&learned),
	})

	resp := exchangeLocal(t, srv, question("example.com."))
	if len(resp.Answer) != 1 || learned[0] != "203.0.113.10" {
		t.Fatalf("answer=%v learned=%v", resp.Answer, learned)
	}
}

func allowOnly(patterns ...string) interface{ Allows(string) bool } {
	eng, err := policy.New(patterns)
	if err != nil {
		panic(err)
	}
	return eng
}

type fakeUpstreamFunc struct {
	fn func(q string) *dns.Msg
}

func fakeUpstream(fn func(q string) *dns.Msg) *fakeUpstreamFunc {
	return &fakeUpstreamFunc{fn: fn}
}

func (u *fakeUpstreamFunc) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	var q string
	if len(req.Question) > 0 {
		q = req.Question[0].Name
	}
	return u.fn(q), nil
}

type fakeUpstreamAnswerFunc struct {
	name string
	ip   string
	ttl  uint32
}

func fakeUpstreamAnswer(name, ip string, ttl uint32) *fakeUpstreamAnswerFunc {
	return &fakeUpstreamAnswerFunc{name: name, ip: ip, ttl: ttl}
}

func (u *fakeUpstreamAnswerFunc) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:   u.name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    u.ttl,
			},
			A: net.ParseIP(u.ip),
		},
	}
	return resp, nil
}

type noopTrustWriter struct{}

func (noopTrustWriter) Allow(context.Context, ebpf.TrustEntry) error { return nil }

type trustWriterCapture struct {
	learned *[]string
}

func captureTrustWriter(learned *[]string) *trustWriterCapture {
	return &trustWriterCapture{learned: learned}
}

func (w *trustWriterCapture) Allow(ctx context.Context, entry ebpf.TrustEntry) error {
	*w.learned = append(*w.learned, entry.IPv4.String())
	return nil
}

type responseRecorder struct {
	msg *dns.Msg
}

func exchangeLocal(t *testing.T, srv *Server, req *dns.Msg) *dns.Msg {
	t.Helper()
	w := &responseRecorder{}
	srv.ServeDNS(w, req)
	if w.msg == nil {
		t.Fatalf("no response written")
	}
	return w.msg
}

func question(name string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeA)
	return m
}

func (w *responseRecorder) LocalAddr() net.Addr  { return &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (w *responseRecorder) RemoteAddr() net.Addr { return &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (w *responseRecorder) WriteMsg(m *dns.Msg) error {
	w.msg = m
	return nil
}
func (w *responseRecorder) Write(b []byte) (int, error) { return len(b), nil }
func (w *responseRecorder) Close() error                { return nil }
func (w *responseRecorder) TsigStatus() error           { return nil }
func (w *responseRecorder) TsigTimersOnly(bool)         {}
func (w *responseRecorder) Hijack()                     {}

