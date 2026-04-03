package dnsproxy

import (
	"context"
	"log/slog"
	"time"

	"github.com/miekg/dns"

	"github.com/moolen/nie/internal/config"
	"github.com/moolen/nie/internal/ebpf"
	"github.com/moolen/nie/internal/policy"
)

type Upstream interface {
	Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error)
}

type ServerConfig struct {
	Mode     config.Mode
	Policy   interface{ Allows(string) bool }
	Upstream Upstream
	Trust    ebpf.TrustWriter
	MaxTTL   time.Duration
	Logger   *slog.Logger
}

type Server struct {
	mode     config.Mode
	policy   interface{ Allows(string) bool }
	upstream Upstream
	trust    ebpf.TrustWriter
	maxTTL   time.Duration
	logger   *slog.Logger
}

type noopTrustWriterImpl struct{}

func (noopTrustWriterImpl) Allow(context.Context, ebpf.TrustEntry) error { return nil }

func New(cfg ServerConfig) *Server {
	l := cfg.Logger
	if l == nil {
		l = slog.Default()
	}

	maxTTL := cfg.MaxTTL
	if maxTTL <= 0 {
		maxTTL = 5 * time.Minute
	}

	tw := cfg.Trust
	if tw == nil {
		tw = noopTrustWriterImpl{}
	}

	return &Server{
		mode:     cfg.Mode,
		policy:   cfg.Policy,
		upstream: cfg.Upstream,
		trust:    tw,
		maxTTL:   maxTTL,
		logger:   l,
	}
}

func (s *Server) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	if req == nil {
		return
	}

	host := ""
	if len(req.Question) == 1 {
		host = policy.NormalizeHostname(req.Question[0].Name)
	}

	allowed := s.policy != nil && s.policy.Allows(host)
	denied := !allowed

	if denied && s.mode == config.ModeEnforce {
		resp := new(dns.Msg)
		resp.SetRcode(req, dns.RcodeRefused)
		_ = w.WriteMsg(resp)
		return
	}

	if denied && s.mode == config.ModeAudit {
		s.logger.Info("would_deny_dns", "host", host)
	}

	resp := s.exchangeUpstream(req)
	s.learnARecords(resp)
	_ = w.WriteMsg(resp)
}

func (s *Server) exchangeUpstream(req *dns.Msg) *dns.Msg {
	if s.upstream == nil {
		resp := new(dns.Msg)
		resp.SetRcode(req, dns.RcodeServerFailure)
		return resp
	}

	resp, err := s.upstream.Exchange(context.Background(), req)
	if err != nil || resp == nil {
		fallback := new(dns.Msg)
		fallback.SetRcode(req, dns.RcodeServerFailure)
		return fallback
	}
	return resp
}

func (s *Server) learnARecords(resp *dns.Msg) {
	if resp == nil || s.trust == nil {
		return
	}

	now := time.Now()
	ctx := context.Background()

	for _, rr := range resp.Answer {
		a, ok := rr.(*dns.A)
		if !ok {
			continue
		}

		entry, err := ebpf.NewEntry(a.A.String(), rr.Header().Ttl, now, s.maxTTL)
		if err != nil {
			continue
		}
		_ = s.trust.Allow(ctx, entry)
	}
}
