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

// dnsListenerLifecycle adapts internal/dnsproxy (which is a dns.Handler) into a
// runnable network listener lifecycle for the CLI.
type dnsServer interface {
	ActivateAndServe() error
	ShutdownContext(context.Context) error
}

type dnsListenerLifecycle struct {
	addr    string
	handler dns.Handler

	udp dnsServer
	tcp dnsServer
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
	var firstErr error

	if d.tcp != nil {
		if err := d.tcp.ShutdownContext(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if d.udp != nil {
		if err := d.udp.ShutdownContext(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

type dnsClientUpstream struct {
	addr string
}

func (u dnsClientUpstream) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	c := &dns.Client{}
	resp, _, err := c.ExchangeContext(ctx, req, u.addr)
	return resp, err
}

type policyAllows interface {
	Allows(string) bool
}

type ebpfManagerLifecycle interface {
	runtime.Lifecycle
	TrustWriter() (ebpf.TrustWriter, error)
	EventReader() (ebpf.EventReader, error)
}

type dnsProxyConfig = dnsproxy.ServerConfig

type componentBuilders struct {
	newPolicy          func(allow []string) (policyAllows, error)
	newEBPFManager     func(cfg config.Config) (ebpfManagerLifecycle, error)
	newRedirectManager func(cfg config.Config) (runtime.Lifecycle, error)
	newDNSProxy        func(cfg dnsProxyConfig) dns.Handler
	newDNSLifecycle    func(addr string, handler dns.Handler) runtime.Lifecycle
}

type liveTrustWriter struct {
	source interface {
		TrustWriter() (ebpf.TrustWriter, error)
	}
}

func (w liveTrustWriter) Allow(ctx context.Context, entry ebpf.TrustEntry) error {
	writer, err := w.source.TrustWriter()
	if err != nil {
		return err
	}
	return writer.Allow(ctx, entry)
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
	ctx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	if err := run(ctx, cfg, logger, componentBuilders{}, func() (context.Context, context.CancelFunc) {
		return context.WithTimeout(context.Background(), 5*time.Second)
	}); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func run(
	ctx context.Context,
	cfg config.Config,
	logger *slog.Logger,
	builders componentBuilders,
	newStopContext func() (context.Context, context.CancelFunc),
) error {
	svc, ebpfMgr, err := buildRuntimeService(cfg, logger, builders)
	if err != nil {
		return err
	}

	if err := svc.Start(ctx); err != nil {
		return fmt.Errorf("start: %w", err)
	}

	var stopAuditLogger func()
	if cfg.Mode == config.ModeAudit {
		stopAuditLogger, err = startAuditEgressLogger(ctx, logger, ebpfMgr)
		if err != nil {
			stopCtx, cancel := newStopContext()
			defer cancel()
			_ = svc.Stop(stopCtx)
			return fmt.Errorf("start egress event logger: %w", err)
		}
	}

	<-ctx.Done()

	if stopAuditLogger != nil {
		stopAuditLogger()
	}

	stopCtx, cancel := newStopContext()
	defer cancel()
	if err := svc.Stop(stopCtx); err != nil {
		return fmt.Errorf("stop: %w", err)
	}
	return nil
}

func buildComponents(cfg config.Config, logger *slog.Logger, builders componentBuilders) (runtime.Service, error) {
	svc, _, err := buildRuntimeService(cfg, logger, builders)
	return svc, err
}

func buildRuntimeService(cfg config.Config, logger *slog.Logger, builders componentBuilders) (runtime.Service, ebpfManagerLifecycle, error) {
	builders = builders.withDefaults(logger)

	p, err := builders.newPolicy(cfg.Policy.Allow)
	if err != nil {
		return runtime.Service{}, nil, fmt.Errorf("build policy: %w", err)
	}
	if len(cfg.DNS.Upstreams) == 0 {
		return runtime.Service{}, nil, fmt.Errorf("load config: dns.upstreams must contain at least one upstream")
	}
	upstream := dnsClientUpstream{addr: cfg.DNS.Upstreams[0]}

	ebpfMgr, err := builders.newEBPFManager(cfg)
	if err != nil {
		return runtime.Service{}, nil, fmt.Errorf("build ebpf manager: %w", err)
	}
	redirectMgr, err := builders.newRedirectManager(cfg)
	if err != nil {
		return runtime.Service{}, nil, fmt.Errorf("build redirect manager: %w", err)
	}

	dnsHandler := builders.newDNSProxy(dnsProxyConfig{
		Mode:     cfg.Mode,
		Policy:   p,
		Upstream: upstream,
		Trust:    liveTrustWriter{source: ebpfMgr},
		Logger:   logger,
	})
	dnsLC := builders.newDNSLifecycle(cfg.DNS.Listen, dnsHandler)

	return runtime.Service{
		Redirect: redirectMgr,
		EBPF:     ebpfMgr,
		DNS:      dnsLC,
	}, ebpfMgr, nil
}

func startAuditEgressLogger(ctx context.Context, logger *slog.Logger, source interface {
	EventReader() (ebpf.EventReader, error)
}) (func(), error) {
	reader, err := source.EventReader()
	if err != nil {
		return nil, err
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		logAuditEgressEvents(ctx, logger, reader)
	}()

	return func() {
		_ = reader.Close()
		<-done
	}, nil
}

func logAuditEgressEvents(ctx context.Context, logger *slog.Logger, reader ebpf.EventReader) {
	for {
		event, err := reader.Read()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			logger.Error("read_egress_event", "err", err)
			return
		}
		if event.Action != ebpf.EgressActionAllow {
			continue
		}

		logger.Info("would_deny_egress",
			"dst", event.Destination.String(),
			"reason", event.Reason.String(),
		)
	}
}

func (b componentBuilders) withDefaults(logger *slog.Logger) componentBuilders {
	if b.newPolicy == nil {
		b.newPolicy = func(allow []string) (policyAllows, error) {
			return policy.New(allow)
		}
	}
	if b.newEBPFManager == nil {
		b.newEBPFManager = func(cfg config.Config) (ebpfManagerLifecycle, error) {
			return ebpf.NewManager(ebpf.ManagerConfig{
				Interface:  cfg.Interface,
				Mode:       cfg.Mode,
				BypassMark: uint32(cfg.DNS.Mark),
			}, ebpf.Dependencies{})
		}
	}
	if b.newRedirectManager == nil {
		b.newRedirectManager = func(cfg config.Config) (runtime.Lifecycle, error) {
			_, portStr, err := net.SplitHostPort(cfg.DNS.Listen)
			if err != nil {
				return nil, fmt.Errorf("parse dns listen address: %w", err)
			}
			port, err := strconv.Atoi(portStr)
			if err != nil {
				return nil, fmt.Errorf("parse dns listen port: %w", err)
			}
			return redirect.NewManager(redirect.Config{
				ListenPort: port,
				Mark:       uint32(cfg.DNS.Mark),
			}, redirect.Dependencies{})
		}
	}
	if b.newDNSProxy == nil {
		b.newDNSProxy = func(cfg dnsProxyConfig) dns.Handler {
			return dnsproxy.New(cfg)
		}
	}
	if b.newDNSLifecycle == nil {
		b.newDNSLifecycle = func(addr string, handler dns.Handler) runtime.Lifecycle {
			return &dnsListenerLifecycle{
				addr:    addr,
				handler: handler,
			}
		}
	}
	return b
}
