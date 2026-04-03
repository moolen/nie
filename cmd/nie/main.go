package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/miekg/dns"

	"github.com/moolen/nie/internal/config"
	"github.com/moolen/nie/internal/dnsproxy"
	"github.com/moolen/nie/internal/ebpf"
	"github.com/moolen/nie/internal/policy"
	"github.com/moolen/nie/internal/redirect"
	"github.com/moolen/nie/internal/runtime"
)

type noopLifecycle struct {
	name   string
	logger *slog.Logger
}

func (n noopLifecycle) Start(context.Context) error {
	if n.logger != nil {
		n.logger.Warn("lifecycle_noop_start", "component", n.name)
	}
	return nil
}

func (n noopLifecycle) Stop(context.Context) error {
	if n.logger != nil {
		n.logger.Warn("lifecycle_noop_stop", "component", n.name)
	}
	return nil
}

// dnsListenerLifecycle adapts internal/dnsproxy (which is a dns.Handler) into a
// runnable network listener lifecycle for the CLI.
type dnsListenerLifecycle struct {
	addr    string
	handler dns.Handler

	udp *dns.Server
	tcp *dns.Server
}

func (d *dnsListenerLifecycle) Start(context.Context) error {
	pc, err := net.ListenPacket("udp", d.addr)
	if err != nil {
		return err
	}

	ln, err := net.Listen("tcp", d.addr)
	if err != nil {
		_ = pc.Close()
		return err
	}

	d.udp = &dns.Server{PacketConn: pc, Handler: d.handler}
	d.tcp = &dns.Server{Listener: ln, Handler: d.handler}

	go func() { _ = d.udp.ActivateAndServe() }()
	go func() { _ = d.tcp.ActivateAndServe() }()
	return nil
}

func (d *dnsListenerLifecycle) Stop(ctx context.Context) error {
	if d.tcp != nil {
		if err := d.tcp.ShutdownContext(ctx); err != nil {
			return err
		}
	}
	if d.udp != nil {
		return d.udp.ShutdownContext(ctx)
	}
	return nil
}

type dnsClientUpstream struct {
	addr string
}

func (u dnsClientUpstream) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	c := &dns.Client{}
	resp, _, err := c.ExchangeContext(ctx, req, u.addr)
	return resp, err
}

func main() {
	var configPath string
	flag.StringVar(&configPath, "config", "", "path to YAML config")
	flag.Parse()

	if configPath == "" {
		_, _ = fmt.Fprintln(os.Stderr, "missing required -config")
		os.Exit(2)
	}

	raw, err := os.ReadFile(configPath)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "read config: %v\n", err)
		os.Exit(1)
	}

	cfg, err := config.Load(raw)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "load config: %v\n", err)
		os.Exit(1)
	}

	logger := slog.Default()

	p, err := policy.New(cfg.Policy.Allow)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "build policy: %v\n", err)
		os.Exit(1)
	}

	if len(cfg.DNS.Upstreams) == 0 {
		_, _ = fmt.Fprintln(os.Stderr, "load config: dns.upstreams must contain at least one upstream")
		os.Exit(1)
	}
	upstream := dnsClientUpstream{addr: cfg.DNS.Upstreams[0]}

	dnsHandler := dnsproxy.New(dnsproxy.ServerConfig{
		Mode:     cfg.Mode,
		Policy:   p,
		Upstream: upstream,
		// Trust: nil (noop) until an eBPF-backed TrustWriter exists.
		Logger: logger,
	})

	redirectLC := buildRedirectNoop(cfg, logger)
	ebpfLC := buildEBPFNoop(logger)
	dnsLC := &dnsListenerLifecycle{
		addr:    cfg.DNS.Listen,
		handler: dnsHandler,
	}

	svc := runtime.Service{
		Redirect: redirectLC,
		EBPF:     ebpfLC,
		DNS:      dnsLC,
	}

	ctx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	if err := svc.Start(ctx); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "start: %v\n", err)
		os.Exit(1)
	}

	<-ctx.Done()

	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := svc.Stop(stopCtx); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "stop: %v\n", err)
		os.Exit(1)
	}
}

func buildRedirectNoop(cfg config.Config, logger *slog.Logger) runtime.Lifecycle {
	_, portStr, err := net.SplitHostPort(cfg.DNS.Listen)
	if err != nil {
		return noopLifecycle{name: "redirect", logger: logger}
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return noopLifecycle{name: "redirect", logger: logger}
	}

	rules := redirect.RenderRules(redirect.Config{
		ListenPort: port,
		Mark:       uint32(cfg.DNS.Mark),
	})
	logger.Warn("redirect_rules_rendered_but_not_applied", "rules", rules)
	return noopLifecycle{name: "redirect", logger: logger}
}

func buildEBPFNoop(logger *slog.Logger) runtime.Lifecycle {
	// internal/ebpf currently exposes loader utilities and TrustWriter helpers,
	// but no runnable manager yet. Keep the lifecycle explicit.
	_ = ebpf.PinnedPaths("/sys/fs/bpf/nie")
	return noopLifecycle{name: "ebpf", logger: logger}
}
