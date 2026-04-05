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
	Upstream   Upstream
	Reconciler interface {
		ReconcileHost(context.Context, string, []ebpf.TrustEntry) error
	}
	Trust  ebpf.TrustWriter
	MaxTTL time.Duration
	Logger *slog.Logger
}

type Server struct {
	mode      config.Mode
	policy    interface{ Allows(string) bool }
	trustPlan interface {
		PortsForHost(string) ([]uint16, bool)
	}
	upstream   Upstream
	reconciler interface {
		ReconcileHost(context.Context, string, []ebpf.TrustEntry) error
	}
	maxTTL  time.Duration
	logger  *slog.Logger
	timeout time.Duration
}

type noopTrustWriterImpl struct{}

func (noopTrustWriterImpl) Allow(context.Context, ebpf.TrustEntry) error { return nil }

type trustWriterReconciler struct {
	writer ebpf.TrustWriter
}

func (r trustWriterReconciler) ReconcileHost(ctx context.Context, _ string, entries []ebpf.TrustEntry) error {
	for _, entry := range entries {
		if err := r.writer.Allow(ctx, entry); err != nil {
			return err
		}
	}
	return nil
}

type denyAllPolicy struct{}

func (denyAllPolicy) Allows(string) bool { return false }

type noopTrustPlanImpl struct{}

func (noopTrustPlanImpl) PortsForHost(string) ([]uint16, bool) { return nil, false }

type noopReconcilerImpl struct{}

func (noopReconcilerImpl) ReconcileHost(context.Context, string, []ebpf.TrustEntry) error { return nil }

func New(cfg ServerConfig) *Server {
	l := cfg.Logger
	if l == nil {
		l = slog.Default()
	}

	maxTTL := cfg.MaxTTL
	if maxTTL <= 0 {
		maxTTL = 5 * time.Minute
	}

	p := cfg.Policy
	if p == nil {
		p = denyAllPolicy{}
		l.Warn("missing_dns_policy_default_deny")
	}
	tp := cfg.TrustPlan
	if tp == nil {
		tp = noopTrustPlanImpl{}
	}
	reconciler := cfg.Reconciler
	if reconciler == nil {
		tw := cfg.Trust
		if tw == nil {
			reconciler = noopReconcilerImpl{}
		} else {
			reconciler = trustWriterReconciler{writer: tw}
		}
	}

	return &Server{
		mode:       cfg.Mode,
		policy:     p,
		trustPlan:  tp,
		upstream:   cfg.Upstream,
		reconciler: reconciler,
		maxTTL:     maxTTL,
		logger:     l,
		timeout:    defaultUpstreamTimeout,
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
	if resp == nil || s.reconciler == nil {
		return
	}
	if resp.Rcode != dns.RcodeSuccess {
		return
	}

	ports, ok := s.trustPlan.PortsForHost(host)
	if !ok || len(ports) == 0 {
		return
	}
	acceptedNames := acceptedAnswerNames(host, resp.Answer)
	if len(acceptedNames) == 0 {
		return
	}

	now := time.Now()
	ctx := context.Background()
	entries := make([]ebpf.TrustEntry, 0, len(resp.Answer)*len(ports))
	type destinationKey struct {
		ip   [4]byte
		port uint16
	}
	seen := make(map[destinationKey]struct{})

	for _, rr := range resp.Answer {
		a, ok := rr.(*dns.A)
		if !ok {
			continue
		}
		if _, ok := acceptedNames[policy.NormalizeHostname(a.Hdr.Name)]; !ok {
			continue
		}

		for _, port := range ports {
			entry, err := ebpf.NewEntry(a.A.String(), port, rr.Header().Ttl, now, s.maxTTL)
			if err != nil {
				continue
			}
			key := destinationKey{ip: entry.IPv4.As4(), port: entry.Port}
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			entries = append(entries, entry)
		}
	}

	_ = s.reconciler.ReconcileHost(ctx, host, entries)
}

func acceptedAnswerNames(host string, answers []dns.RR) map[string]struct{} {
	host = policy.NormalizeHostname(host)
	if host == "" {
		return nil
	}

	accepted := map[string]struct{}{host: {}}
	for {
		changed := false
		for _, rr := range answers {
			cname, ok := rr.(*dns.CNAME)
			if !ok {
				continue
			}
			name := policy.NormalizeHostname(cname.Hdr.Name)
			if _, ok := accepted[name]; !ok {
				continue
			}
			target := policy.NormalizeHostname(cname.Target)
			if target == "" {
				continue
			}
			if _, ok := accepted[target]; ok {
				continue
			}
			accepted[target] = struct{}{}
			changed = true
		}
		if !changed {
			return accepted
		}
	}
}
