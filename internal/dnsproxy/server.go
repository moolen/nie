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

const defaultUpstreamTimeout = 5 * time.Second

type Upstream interface {
	Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error)
}

type ServerConfig struct {
	Mode      config.Mode
	Policy    interface{ Allows(string) bool }
	TrustPlan interface {
		PortsForHost(string) ([]uint16, bool)
	}
	Upstream Upstream
	Trust    ebpf.TrustWriter
	MaxTTL   time.Duration
	Logger   *slog.Logger
}

type Server struct {
	mode      config.Mode
	policy    interface{ Allows(string) bool }
	trustPlan interface {
		PortsForHost(string) ([]uint16, bool)
	}
	upstream Upstream
	trust    ebpf.TrustWriter
	maxTTL   time.Duration
	logger   *slog.Logger
	timeout  time.Duration
}

type noopTrustWriterImpl struct{}

func (noopTrustWriterImpl) Allow(context.Context, ebpf.TrustEntry) error { return nil }

type denyAllPolicy struct{}

func (denyAllPolicy) Allows(string) bool { return false }

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

	p := cfg.Policy
	if p == nil {
		p = denyAllPolicy{}
		l.Warn("missing_dns_policy_default_deny")
	}

	return &Server{
		mode:      cfg.Mode,
		policy:    p,
		trustPlan: cfg.TrustPlan,
		upstream:  cfg.Upstream,
		trust:     tw,
		maxTTL:    maxTTL,
		logger:    l,
		timeout:   defaultUpstreamTimeout,
	}
}

func (s *Server) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	if req == nil {
		return
	}

	if len(req.Question) != 1 {
		resp := new(dns.Msg)
		resp.SetRcode(req, dns.RcodeFormatError)
		_ = w.WriteMsg(resp)
		return
	}
	host := policy.NormalizeHostname(req.Question[0].Name)

	allowed := s.policy.Allows(host)
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
	s.learnARecords(host, resp)
	_ = w.WriteMsg(resp)
}

func (s *Server) exchangeUpstream(req *dns.Msg) *dns.Msg {
	if s.upstream == nil {
		resp := new(dns.Msg)
		resp.SetRcode(req, dns.RcodeServerFailure)
		return resp
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	resp, err := s.upstream.Exchange(ctx, req)
	if err != nil || resp == nil {
		fallback := new(dns.Msg)
		fallback.SetRcode(req, dns.RcodeServerFailure)
		return fallback
	}
	return resp
}

func (s *Server) learnARecords(host string, resp *dns.Msg) {
	if resp == nil || s.trust == nil || s.trustPlan == nil {
		return
	}

	ports, ok := s.trustPlan.PortsForHost(host)
	if !ok {
		return
	}

	now := time.Now()
	ctx := context.Background()

	for _, rr := range resp.Answer {
		a, ok := rr.(*dns.A)
		if !ok {
			continue
		}

		for _, port := range ports {
			entry, err := ebpf.NewEntry(a.A.String(), port, rr.Header().Ttl, now, s.maxTTL)
			if err != nil {
				continue
			}
			_ = s.trust.Allow(ctx, entry)
		}
	}
}
