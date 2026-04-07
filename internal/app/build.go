package app

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
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
	"github.com/moolen/nie/internal/trustsync"
)

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
	validateInterface  func(iface string) error
	resolveConfig      func(cfg config.Config) (resolvedRuntimeConfig, error)
}

type liveTrustReconciler struct {
	source interface {
		TrustWriter() (ebpf.TrustWriter, error)
	}
	sync interface {
		ReconcileHostAnswers(host string, destinations []trustsync.Destination)
	}
}

type liveTrustDeleter struct {
	source interface {
		TrustWriter() (ebpf.TrustWriter, error)
	}
}

type liveTrustRefresher struct {
	source interface {
		TrustWriter() (ebpf.TrustWriter, error)
	}
}

func upstreamTLSConfig(serverName string) *tls.Config {
	return &tls.Config{
		ServerName: serverName,
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
	}
}

func upstreamHTTP1TLSConfig(serverName string) *tls.Config {
	return &tls.Config{
		ServerName: serverName,
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
	}
}

func (r liveTrustReconciler) ReconcileHost(ctx context.Context, host string, entries []ebpf.TrustEntry) error {
	writer, err := r.source.TrustWriter()
	if err != nil {
		return err
	}
	destinations := make([]trustsync.Destination, 0, len(entries))
	var firstErr error
	for _, entry := range entries {
		if err := writer.Allow(ctx, entry); err != nil && firstErr == nil {
			firstErr = err
		}
		destinations = append(destinations, trustsync.Destination{
			IP:       entry.IPv4,
			Port:     entry.Port,
			Protocol: trustsync.ProtocolTCP,
		})
	}
	r.sync.ReconcileHostAnswers(host, destinations)
	return firstErr
}

func (d liveTrustDeleter) DeleteDestination(ctx context.Context, dst trustsync.Destination) error {
	writer, err := d.source.TrustWriter()
	if err != nil {
		return err
	}
	deleter, ok := writer.(ebpf.TrustDeleter)
	if !ok {
		return fmt.Errorf("trust writer does not support delete")
	}
	return deleter.Delete(ctx, dst.IP, dst.Port)
}

func (r liveTrustRefresher) RefreshDestination(ctx context.Context, dst trustsync.Destination, expiresAt time.Time) error {
	writer, err := r.source.TrustWriter()
	if err != nil {
		return err
	}
	return writer.Allow(ctx, ebpf.TrustEntry{
		IPv4:      dst.IP,
		Port:      dst.Port,
		ExpiresAt: expiresAt,
	})
}

func buildComponents(cfg config.Config, logger *slog.Logger, builders componentBuilders) (runtime.Service, error) {
	svc, _, err := buildRuntimeService(cfg, logger, builders)
	return svc, err
}

func buildRuntimeService(cfg config.Config, logger *slog.Logger, builders componentBuilders) (runtime.Service, ebpfManagerLifecycle, error) {
	builders = builders.withDefaults(logger)
	resolved, err := builders.resolveConfig(cfg)
	if err != nil {
		return runtime.Service{}, nil, fmt.Errorf("resolve runtime config: %w", err)
	}
	runtimeCfg := cfg
	runtimeCfg.Interface = config.InterfaceSelector{
		Mode: "explicit",
		Name: resolved.Interface,
	}
	runtimeCfg.DNS.Upstreams = config.UpstreamSelector{
		Mode:      "explicit",
		Addresses: append([]string(nil), resolved.Upstreams...),
	}

	if err := builders.validateInterface(runtimeCfg.Interface.Name); err != nil {
		return runtime.Service{}, nil, fmt.Errorf("validate protected interface: %w", err)
	}

	p, err := builders.newPolicy(runtimeCfg.Policy.Allow)
	if err != nil {
		return runtime.Service{}, nil, fmt.Errorf("build policy: %w", err)
	}
	markedDialer, err := builders.newMarkedDialer(uint32(runtimeCfg.DNS.Mark))
	if err != nil {
		return runtime.Service{}, nil, fmt.Errorf("build marked dialer: %w", err)
	}
	if len(runtimeCfg.DNS.Upstreams.Addresses) == 0 {
		return runtime.Service{}, nil, fmt.Errorf("load config: dns.upstreams must contain at least one upstream")
	}
	upstream := dnsClientUpstream{
		addrs:  append([]string(nil), runtimeCfg.DNS.Upstreams.Addresses...),
		dialer: markedDialer,
	}

	ebpfMgr, err := builders.newEBPFManager(runtimeCfg)
	if err != nil {
		return runtime.Service{}, nil, fmt.Errorf("build ebpf manager: %w", err)
	}
	redirectMgr, err := builders.newRedirectManager(runtimeCfg)
	if err != nil {
		return runtime.Service{}, nil, fmt.Errorf("build redirect manager: %w", err)
	}

	trustPlan, err := policy.NewTrustPlan(runtimeCfg.Policy.Allow, httpsTrustedPorts(runtimeCfg.HTTPS.Ports), mitmTrustRules(runtimeCfg.HTTPS.MITM.Rules))
	if err != nil {
		return runtime.Service{}, nil, fmt.Errorf("build dns trust plan: %w", err)
	}
	trustService := trustsync.New(trustsync.ServiceConfig{
		MaxStaleHold:  runtimeCfg.Trust.MaxStaleHold,
		SweepInterval: runtimeCfg.Trust.SweepInterval,
		Deleter:       liveTrustDeleter{source: ebpfMgr},
		Refresher:     liveTrustRefresher{source: ebpfMgr},
	})
	trustReconciler := liveTrustReconciler{
		source: ebpfMgr,
		sync:   trustService,
	}
	httpPolicy, err := httppolicy.New(mitmHTTPRules(runtimeCfg.HTTPS.MITM.Rules))
	if err != nil {
		return runtime.Service{}, nil, fmt.Errorf("build https mitm policy: %w", err)
	}
	authority, err := mitm.EnsureCA(mitm.CAPaths{
		CertFile: runtimeCfg.HTTPS.CA.CertFile,
		KeyFile:  runtimeCfg.HTTPS.CA.KeyFile,
	})
	if err != nil {
		return runtime.Service{}, nil, fmt.Errorf("ensure https mitm ca: %w", err)
	}
	leafCache := mitm.NewLeafCache(authority, nil)
	httpsProxy, err := mitm.NewProxy(mitm.ProxyConfig{
		Mode:             runtimeCfg.Mode,
		MissingSNIAction: httppolicy.Action(runtimeCfg.HTTPS.SNI.Missing),
		DefaultAction:    httppolicy.Action(runtimeCfg.HTTPS.MITM.Default),
	}, mitm.ProxyDependencies{
		Logger:           logger,
		MITMPolicy:       httpPolicy,
		HostnamePolicy:   p,
		LeafCertificates: leafCache,
		OpenUpstreamHTTP1TLS: func(ctx context.Context, serverName string, destination netip.AddrPort) (net.Conn, error) {
			rawConn, err := markedDialer.DialContext(ctx, "tcp", destination.String())
			if err != nil {
				return nil, err
			}
			tlsConn := tls.Client(rawConn, upstreamHTTP1TLSConfig(serverName))
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				_ = rawConn.Close()
				return nil, err
			}
			return tlsConn, nil
		},
		OpenUpstreamHTTP2TLS: func(ctx context.Context, serverName string, destination netip.AddrPort) (net.Conn, error) {
			rawConn, err := markedDialer.DialContext(ctx, "tcp", destination.String())
			if err != nil {
				return nil, err
			}
			tlsConn := tls.Client(rawConn, upstreamTLSConfig(serverName))
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
		ListenAddr: runtimeCfg.HTTPS.Listen,
	}, mitm.ServiceDependencies{
		Handler: httpsProxy,
	})
	if err != nil {
		return runtime.Service{}, nil, fmt.Errorf("build https service: %w", err)
	}

	dnsHandler := builders.newDNSProxy(dnsProxyConfig{
		Mode:       runtimeCfg.Mode,
		Policy:     p,
		TrustPlan:  trustPlan,
		Upstream:   upstream,
		Reconciler: trustReconciler,
		Logger:     logger,
	})
	dnsLC := builders.newDNSLifecycle(runtimeCfg.DNS.Listen, dnsHandler)

	return runtime.Service{
		Redirect: redirectMgr,
		EBPF:     ebpfMgr,
		Trust:    trustService,
		DNS:      dnsLC,
		HTTPS:    httpsService,
	}, ebpfMgr, nil
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
				Interface:  cfg.Interface.Name,
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
	if b.validateInterface == nil {
		b.validateInterface = validateProtectedInterface
	}
	if b.resolveConfig == nil {
		b.resolveConfig = func(cfg config.Config) (resolvedRuntimeConfig, error) {
			return resolveRuntimeConfig(context.Background(), cfg, resolverDeps{})
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

func httpsTrustedPorts(ports []int) []uint16 {
	out := make([]uint16, 0, len(ports))
	for _, port := range ports {
		if port <= 0 || port > 65535 {
			continue
		}
		out = append(out, uint16(port))
	}
	return out
}
