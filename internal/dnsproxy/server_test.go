package dnsproxy

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

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
		Mode:   config.ModeAudit,
		Policy: allowOnly("*.github.com"),
		TrustPlan: trustPlanForTests(map[string][]uint16{
			"example.com": {0},
		}),
		Upstream: fakeUpstreamAnswer("example.com.", "203.0.113.10", 60),
		Trust:    captureTrustWriter(&learned),
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	})

	resp := exchangeLocal(t, srv, question("example.com."))
	if len(resp.Answer) != 1 || len(learned) != 1 || learned[0] != "203.0.113.10" {
		t.Fatalf("answer=%v learned=%v", resp.Answer, learned)
	}
}

func TestServeDNS_AllowedHostForwardsUpstream(t *testing.T) {
	var calls int
	srv := New(ServerConfig{
		Mode:   config.ModeEnforce,
		Policy: allowOnly("*.github.com"),
		Upstream: fakeUpstream(func(q string) *dns.Msg {
			calls++
			return replyWithRecords(question(q), &dns.A{
				Hdr: dns.RR_Header{
					Name:   q,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				A: net.ParseIP("203.0.113.20"),
			})
		}),
		Trust: noopTrustWriter{},
	})

	resp := exchangeLocal(t, srv, question("api.github.com."))
	if calls != 1 {
		t.Fatalf("upstream calls = %d, want 1", calls)
	}
	if resp.Rcode == dns.RcodeRefused {
		t.Fatalf("Rcode = %d, want not refused", resp.Rcode)
	}
}

func TestServeDNS_IgnoresAAAARecordsForTrustLearning(t *testing.T) {
	var learned []string
	srv := New(ServerConfig{
		Mode:   config.ModeAudit,
		Policy: allowOnly("*.github.com"),
		TrustPlan: trustPlanForTests(map[string][]uint16{
			"api.github.com": {443},
		}),
		Upstream: fakeUpstream(func(q string) *dns.Msg {
			return replyWithRecords(question(q), &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   q,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				AAAA: net.ParseIP("2001:db8::1"),
			})
		}),
		Trust: captureTrustWriter(&learned),
	})

	resp := exchangeLocal(t, srv, question("api.github.com."))
	if len(resp.Answer) != 1 {
		t.Fatalf("answer=%v, want 1 AAAA record", resp.Answer)
	}
	if len(learned) != 0 {
		t.Fatalf("learned=%v, want no IPv4 trust entries", learned)
	}
}

func TestServeDNS_LearnsConfiguredPortsForMITMHost(t *testing.T) {
	var learned []ebpf.TrustEntry
	srv := New(ServerConfig{
		Mode:      config.ModeEnforce,
		Policy:    allowOnly("*.github.com"),
		TrustPlan: trustPlanForTests(map[string][]uint16{"api.github.com": {443, 8443}}),
		Upstream:  fakeUpstreamAnswer("api.github.com.", "203.0.113.10", 60),
		Trust:     captureTrustEntries(&learned),
	})

	_ = exchangeLocal(t, srv, question("api.github.com."))
	if len(learned) != 2 {
		t.Fatalf("learned = %v, want 2 port-specific entries", learned)
	}
}

func TestServeDNS_DoesNotLearnUnrelatedAAnswers(t *testing.T) {
	var learned []ebpf.TrustEntry
	srv := New(ServerConfig{
		Mode:      config.ModeEnforce,
		Policy:    allowOnly("*.github.com"),
		TrustPlan: trustPlanForTests(map[string][]uint16{"api.github.com": {443}}),
		Upstream: fakeUpstream(func(q string) *dns.Msg {
			return replyWithRecords(question(q), &dns.A{
				Hdr: dns.RR_Header{
					Name:   "unrelated.example.com.",
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				A: net.ParseIP("203.0.113.10"),
			})
		}),
		Trust: captureTrustEntries(&learned),
	})

	_ = exchangeLocal(t, srv, question("api.github.com."))
	if len(learned) != 0 {
		t.Fatalf("learned = %v, want no entries", learned)
	}
}

func TestServeDNS_LearnsAAnswersReachableThroughCNAMEChain(t *testing.T) {
	var learned []ebpf.TrustEntry
	srv := New(ServerConfig{
		Mode:      config.ModeEnforce,
		Policy:    allowOnly("*.github.com"),
		TrustPlan: trustPlanForTests(map[string][]uint16{"api.github.com": {443}}),
		Upstream: fakeUpstream(func(q string) *dns.Msg {
			return replyWithRecords(question(q),
				&dns.CNAME{
					Hdr: dns.RR_Header{
						Name:   q,
						Rrtype: dns.TypeCNAME,
						Class:  dns.ClassINET,
						Ttl:    60,
					},
					Target: "edge.github.net.",
				},
				&dns.A{
					Hdr: dns.RR_Header{
						Name:   "edge.github.net.",
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    60,
					},
					A: net.ParseIP("203.0.113.10"),
				},
			)
		}),
		Trust: captureTrustEntries(&learned),
	})

	_ = exchangeLocal(t, srv, question("api.github.com."))
	if len(learned) != 1 || learned[0].IPv4.String() != "203.0.113.10" {
		t.Fatalf("learned = %v, want one entry for 203.0.113.10", learned)
	}
}

func TestServeDNS_DoesNotLearnFromNonSuccessResponses(t *testing.T) {
	var learned []ebpf.TrustEntry
	srv := New(ServerConfig{
		Mode:      config.ModeEnforce,
		Policy:    allowOnly("*.github.com"),
		TrustPlan: trustPlanForTests(map[string][]uint16{"api.github.com": {443}}),
		Upstream: fakeUpstream(func(q string) *dns.Msg {
			resp := replyWithRecords(question(q), &dns.A{
				Hdr: dns.RR_Header{
					Name:   q,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				A: net.ParseIP("203.0.113.10"),
			})
			resp.Rcode = dns.RcodeNameError
			return resp
		}),
		Trust: captureTrustEntries(&learned),
	})

	resp := exchangeLocal(t, srv, question("api.github.com."))
	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("Rcode = %d, want %d", resp.Rcode, dns.RcodeNameError)
	}
	if len(learned) != 0 {
		t.Fatalf("learned = %v, want no entries", learned)
	}
}

func TestServeDNS_DoesNotLearnWhenTrustPlanHasNoMatch(t *testing.T) {
	var learned []ebpf.TrustEntry
	srv := New(ServerConfig{
		Mode:      config.ModeEnforce,
		Policy:    allowOnly("*.github.com"),
		TrustPlan: trustPlanForTests(map[string][]uint16{}),
		Upstream:  fakeUpstreamAnswer("api.github.com.", "203.0.113.10", 60),
		Trust:     captureTrustEntries(&learned),
	})

	_ = exchangeLocal(t, srv, question("api.github.com."))
	if len(learned) != 0 {
		t.Fatalf("learned = %v, want no entries", learned)
	}
}

func TestServeDNS_DoesNotLearnWhenTrustPlanReturnsEmptyPorts(t *testing.T) {
	var learned []ebpf.TrustEntry
	srv := New(ServerConfig{
		Mode:      config.ModeEnforce,
		Policy:    allowOnly("*.github.com"),
		TrustPlan: trustPlanForTests(map[string][]uint16{"api.github.com": {}}),
		Upstream:  fakeUpstreamAnswer("api.github.com.", "203.0.113.10", 60),
		Trust:     captureTrustEntries(&learned),
	})

	_ = exchangeLocal(t, srv, question("api.github.com."))
	if len(learned) != 0 {
		t.Fatalf("learned = %v, want no entries", learned)
	}
}

func TestServeDNS_NormalizesSingleQuestionHostnameBeforePolicyEvaluation(t *testing.T) {
	var seen string
	srv := New(ServerConfig{
		Mode: config.ModeEnforce,
		Policy: policyFunc(func(host string) bool {
			seen = host
			return host == "api.github.com"
		}),
		Upstream: fakeUpstream(func(q string) *dns.Msg {
			return replyWithRecords(question(q))
		}),
		Trust: noopTrustWriter{},
	})

	req := new(dns.Msg)
	req.Question = []dns.Question{{
		Name:   " API.GITHUB.COM. ",
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	}}

	resp := exchangeLocal(t, srv, req)
	if seen != "api.github.com" {
		t.Fatalf("policy saw %q, want %q", seen, "api.github.com")
	}
	if resp.Rcode == dns.RcodeRefused {
		t.Fatalf("Rcode = %d, want not refused", resp.Rcode)
	}
}

func TestServeDNS_AuditDeniedLogsWouldDenyDNS(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	prev := slog.Default()
	slog.SetDefault(logger)
	t.Cleanup(func() { slog.SetDefault(prev) })

	srv := New(ServerConfig{
		Mode:   config.ModeAudit,
		Policy: allowOnly("*.github.com"),
		Upstream: fakeUpstream(func(q string) *dns.Msg {
			return replyWithRecords(question(q))
		}),
		Trust: noopTrustWriter{},
	})

	_ = exchangeLocal(t, srv, question("example.com."))
	if !bytes.Contains(buf.Bytes(), []byte("would_deny_dns")) {
		t.Fatalf("log output %q does not contain would_deny_dns", buf.String())
	}
}

func TestServeDNS_MalformedQuestionSetsFormErr(t *testing.T) {
	tests := []struct {
		name string
		req  *dns.Msg
	}{
		{
			name: "empty question list",
			req:  new(dns.Msg),
		},
		{
			name: "multiple questions",
			req: &dns.Msg{
				Question: []dns.Question{
					{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
					{Name: "api.github.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := New(ServerConfig{
				Mode:   config.ModeEnforce,
				Policy: allowOnly("*.github.com"),
				Upstream: fakeUpstream(func(q string) *dns.Msg {
					t.Fatalf("upstream should not be called for malformed request")
					return nil
				}),
				Trust: noopTrustWriter{},
			})

			resp := exchangeLocal(t, srv, tt.req)
			if resp.Rcode != dns.RcodeFormatError {
				t.Fatalf("Rcode = %d, want %d", resp.Rcode, dns.RcodeFormatError)
			}
		})
	}
}

func TestServeDNS_UpstreamExchangeUsesTimeoutContext(t *testing.T) {
	var gotDeadline time.Time
	srv := New(ServerConfig{
		Mode:   config.ModeEnforce,
		Policy: allowOnly("*.github.com"),
		Upstream: fakeUpstreamWithContext(func(ctx context.Context, q string) *dns.Msg {
			var ok bool
			gotDeadline, ok = ctx.Deadline()
			if !ok {
				t.Fatalf("expected upstream context deadline")
			}
			return replyWithRecords(question(q))
		}),
		Trust: noopTrustWriter{},
	})

	_ = exchangeLocal(t, srv, question("api.github.com."))
	if gotDeadline.IsZero() {
		t.Fatal("upstream context deadline was not recorded")
	}
	if time.Until(gotDeadline) <= 0 {
		t.Fatalf("deadline %v is not in the future", gotDeadline)
	}
}

func TestNew_NilPolicyDefaultsToDenyAllAndLogsWarning(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	srv := New(ServerConfig{
		Mode: config.ModeEnforce,
		Upstream: fakeUpstream(func(q string) *dns.Msg {
			t.Fatalf("upstream should not be called for nil policy in enforce mode")
			return nil
		}),
		Trust:  noopTrustWriter{},
		Logger: logger,
	})

	resp := exchangeLocal(t, srv, question("api.github.com."))
	if resp.Rcode != dns.RcodeRefused {
		t.Fatalf("Rcode = %d, want %d", resp.Rcode, dns.RcodeRefused)
	}
	if !bytes.Contains(buf.Bytes(), []byte("missing_dns_policy_default_deny")) {
		t.Fatalf("log output %q does not contain missing_dns_policy_default_deny", buf.String())
	}
}

func TestNew_NilTrustPlanDefaultsToNoop(t *testing.T) {
	srv := New(ServerConfig{
		Mode:   config.ModeAudit,
		Policy: allowOnly("*.github.com"),
		Upstream: fakeUpstream(func(q string) *dns.Msg {
			return replyWithRecords(question(q))
		}),
		Trust: noopTrustWriter{},
	})

	if srv.trustPlan == nil {
		t.Fatal("trustPlan = nil, want no-op trust plan")
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

type fakeUpstreamWithContextFunc struct {
	fn func(context.Context, string) *dns.Msg
}

func fakeUpstreamWithContext(fn func(context.Context, string) *dns.Msg) *fakeUpstreamWithContextFunc {
	return &fakeUpstreamWithContextFunc{fn: fn}
}

func (u *fakeUpstreamWithContextFunc) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	var q string
	if len(req.Question) > 0 {
		q = req.Question[0].Name
	}
	return u.fn(ctx, q), nil
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
	return replyWithRecords(req, &dns.A{
		Hdr: dns.RR_Header{
			Name:   u.name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    u.ttl,
		},
		A: net.ParseIP(u.ip),
	}), nil
}

type policyFunc func(string) bool

func (f policyFunc) Allows(host string) bool { return f(host) }

func replyWithRecords(req *dns.Msg, records ...dns.RR) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Answer = []dns.RR{}
	resp.Answer = append(resp.Answer, records...)
	return resp
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

type trustEntryCapture struct {
	learned *[]ebpf.TrustEntry
}

func captureTrustEntries(learned *[]ebpf.TrustEntry) *trustEntryCapture {
	return &trustEntryCapture{learned: learned}
}

func (w *trustEntryCapture) Allow(ctx context.Context, entry ebpf.TrustEntry) error {
	*w.learned = append(*w.learned, entry)
	return nil
}

type trustPlanStub struct {
	portsByHost map[string][]uint16
}

func trustPlanForTests(portsByHost map[string][]uint16) *trustPlanStub {
	return &trustPlanStub{portsByHost: portsByHost}
}

func (p *trustPlanStub) PortsForHost(host string) ([]uint16, bool) {
	ports, ok := p.portsByHost[host]
	if !ok {
		return nil, false
	}
	return ports, true
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
