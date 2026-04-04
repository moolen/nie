package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/miekg/dns"

	"github.com/moolen/nie/internal/config"
	"github.com/moolen/nie/internal/dnsproxy"
	"github.com/moolen/nie/internal/ebpf"
	"github.com/moolen/nie/internal/httppolicy"
	"github.com/moolen/nie/internal/mitm"
	"github.com/moolen/nie/internal/netx"
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
	addr   string
	dialer *net.Dialer
}

func (u dnsClientUpstream) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	c := &dns.Client{Dialer: u.dialer}
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
	newMarkedDialer    func(mark uint32) (*net.Dialer, error)
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
	markedDialer, err := builders.newMarkedDialer(uint32(cfg.DNS.Mark))
	if err != nil {
		return runtime.Service{}, nil, fmt.Errorf("build marked dialer: %w", err)
	}
	if len(cfg.DNS.Upstreams) == 0 {
		return runtime.Service{}, nil, fmt.Errorf("load config: dns.upstreams must contain at least one upstream")
	}
	upstream := dnsClientUpstream{
		addr:   cfg.DNS.Upstreams[0],
		dialer: markedDialer,
	}

	ebpfMgr, err := builders.newEBPFManager(cfg)
	if err != nil {
		return runtime.Service{}, nil, fmt.Errorf("build ebpf manager: %w", err)
	}
	redirectMgr, err := builders.newRedirectManager(cfg)
	if err != nil {
		return runtime.Service{}, nil, fmt.Errorf("build redirect manager: %w", err)
	}

	trustPlan, err := policy.NewTrustPlan(cfg.Policy.Allow, mitmTrustRules(cfg.HTTPS.MITM.Rules))
	if err != nil {
		return runtime.Service{}, nil, fmt.Errorf("build dns trust plan: %w", err)
	}
	httpPolicy, err := httppolicy.New(mitmHTTPRules(cfg.HTTPS.MITM.Rules))
	if err != nil {
		return runtime.Service{}, nil, fmt.Errorf("build https mitm policy: %w", err)
	}
	authority, err := mitm.EnsureCA(mitm.CAPaths{
		CertFile: cfg.HTTPS.CA.CertFile,
		KeyFile:  cfg.HTTPS.CA.KeyFile,
	})
	if err != nil {
		return runtime.Service{}, nil, fmt.Errorf("ensure https mitm ca: %w", err)
	}
	leafCache := mitm.NewLeafCache(authority, nil)
	httpsProxy, err := mitm.NewProxy(mitm.ProxyConfig{
		Mode:             cfg.Mode,
		MissingSNIAction: httppolicy.Action(cfg.HTTPS.SNI.Missing),
		DefaultAction:    httppolicy.Action(cfg.HTTPS.MITM.Default),
	}, mitm.ProxyDependencies{
		Logger:           logger,
		MITMPolicy:       httpPolicy,
		HostnamePolicy:   p,
		LeafCertificates: leafCache,
		OpenUpstreamTLS: func(ctx context.Context, serverName string, destination netip.AddrPort) (net.Conn, error) {
			rawConn, err := markedDialer.DialContext(ctx, "tcp", destination.String())
			if err != nil {
				return nil, err
			}
			tlsConn := tls.Client(rawConn, &tls.Config{
				ServerName: serverName,
				MinVersion: tls.VersionTLS12,
				NextProtos: []string{"h2", "http/1.1"},
			})
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				_ = rawConn.Close()
				return nil, err
			}
			return tlsConn, nil
		},
		OpenUpstreamTCP: func(ctx context.Context, destination netip.AddrPort) (net.Conn, error) {
			return markedDialer.DialContext(ctx, "tcp", destination.String())
		},
	})
	if err != nil {
		return runtime.Service{}, nil, fmt.Errorf("build https proxy: %w", err)
	}
	httpsService, err := mitm.NewService(mitm.ServiceConfig{
		ListenAddr: cfg.HTTPS.Listen,
	}, mitm.ServiceDependencies{
		Handler: httpsProxy,
	})
	if err != nil {
		return runtime.Service{}, nil, fmt.Errorf("build https service: %w", err)
	}

	dnsHandler := builders.newDNSProxy(dnsProxyConfig{
		Mode:      cfg.Mode,
		Policy:    p,
		TrustPlan: trustPlan,
		Upstream:  upstream,
		Trust:     liveTrustWriter{source: ebpfMgr},
		Logger:    logger,
	})
	dnsLC := builders.newDNSLifecycle(cfg.DNS.Listen, dnsHandler)

	return runtime.Service{
		Redirect: redirectMgr,
		EBPF:     ebpfMgr,
		DNS:      dnsLC,
		HTTPS:    httpsService,
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
			_, dnsPortStr, err := net.SplitHostPort(cfg.DNS.Listen)
			if err != nil {
				return nil, fmt.Errorf("parse dns listen address: %w", err)
			}
			dnsPort, err := strconv.Atoi(dnsPortStr)
			if err != nil {
				return nil, fmt.Errorf("parse dns listen port: %w", err)
			}
			_, httpsPortStr, err := net.SplitHostPort(cfg.HTTPS.Listen)
			if err != nil {
				return nil, fmt.Errorf("parse https listen address: %w", err)
			}
			httpsPort, err := strconv.Atoi(httpsPortStr)
			if err != nil {
				return nil, fmt.Errorf("parse https listen port: %w", err)
			}
			return redirect.NewManager(redirect.Config{
				DNSListenPort:   dnsPort,
				HTTPSListenPort: httpsPort,
				HTTPSPorts:      append([]int(nil), cfg.HTTPS.Ports...),
				Mark:            uint32(cfg.DNS.Mark),
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
	if b.newMarkedDialer == nil {
		b.newMarkedDialer = func(mark uint32) (*net.Dialer, error) {
			return netx.NewMarkedDialer(mark)
		}
	}
	return b
}

func mitmTrustRules(rules []config.HTTPSMITMRule) []policy.MITMHostPortRule {
	out := make([]policy.MITMHostPortRule, 0, len(rules))
	for _, rule := range rules {
		out = append(out, policy.MITMHostPortRule{
			Host: rule.Host,
			Port: uint16(rule.Port),
		})
	}
	return out
}

func mitmHTTPRules(rules []config.HTTPSMITMRule) []httppolicy.Rule {
	out := make([]httppolicy.Rule, 0, len(rules))
	for _, rule := range rules {
		out = append(out, httppolicy.Rule{
			Host:    rule.Host,
			Port:    uint16(rule.Port),
			Methods: append([]string(nil), rule.Methods...),
			Paths:   append([]string(nil), rule.Paths...),
			Action:  httppolicy.Action(rule.Action),
		})
	}
	return out
}
