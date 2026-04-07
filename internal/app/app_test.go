package app

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/moolen/nie/internal/config"
	"github.com/moolen/nie/internal/ebpf"
	"github.com/moolen/nie/internal/runtime"
	"github.com/moolen/nie/internal/trustsync"
)

func TestAppPackageScaffold(t *testing.T) {
	var runFn func(context.Context, config.Config, *slog.Logger) error = Run
	var buildFn func(config.Config, *slog.Logger, componentBuilders) (runtime.Service, error) = buildComponents

	if runFn == nil {
		t.Fatal("Run = nil")
	}
	if buildFn == nil {
		t.Fatal("buildComponents = nil")
	}
}

func TestValidateProtectedInterfaceAllowsIPv4Only(t *testing.T) {
	err := validateProtectedInterfaceAddrs("eth0", []net.Addr{
		&net.IPNet{IP: net.IPv4(192, 0, 2, 10), Mask: net.CIDRMask(24, 32)},
		&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)},
	})
	if err != nil {
		t.Fatalf("validateProtectedInterfaceAddrs() error = %v, want nil", err)
	}
}

func TestValidateProtectedInterfaceIgnoresIPv6LinkLocal(t *testing.T) {
	err := validateProtectedInterfaceAddrs("eth0", []net.Addr{
		&net.IPNet{IP: net.IPv4(192, 0, 2, 10), Mask: net.CIDRMask(24, 32)},
		&net.IPNet{IP: net.ParseIP("fe80::1234"), Mask: net.CIDRMask(64, 128)},
	})
	if err != nil {
		t.Fatalf("validateProtectedInterfaceAddrs() error = %v, want nil", err)
	}
}

func TestValidateProtectedInterfaceFailsClosedOnIPv6(t *testing.T) {
	err := validateProtectedInterfaceAddrs("eth0", []net.Addr{
		&net.IPNet{IP: net.ParseIP("2001:db8::10"), Mask: net.CIDRMask(64, 128)},
	})
	if err == nil {
		t.Fatal("validateProtectedInterfaceAddrs() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "interface eth0 has IPv6 addresses assigned") {
		t.Fatalf("validateProtectedInterfaceAddrs() error = %q, want IPv6 fail-closed message", err)
	}
}

func TestValidateProtectedInterfaceRejectsUnsupportedAddressType(t *testing.T) {
	err := validateProtectedInterfaceAddrs("eth0", []net.Addr{unsupportedAddr("mystery")})
	if err == nil {
		t.Fatal("validateProtectedInterfaceAddrs() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "unsupported address type") {
		t.Fatalf("validateProtectedInterfaceAddrs() error = %q, want unsupported address type", err)
	}
}

func TestUpstreamTLSConfigAdvertisesHTTP2AndHTTP11(t *testing.T) {
	cfg := upstreamTLSConfig("registry-1.docker.io")

	if cfg.ServerName != "registry-1.docker.io" {
		t.Fatalf("ServerName = %q, want %q", cfg.ServerName, "registry-1.docker.io")
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion = %v, want %v", cfg.MinVersion, tls.VersionTLS12)
	}
	want := []string{"h2", "http/1.1"}
	if !reflect.DeepEqual(cfg.NextProtos, want) {
		t.Fatalf("NextProtos = %v, want %v", cfg.NextProtos, want)
	}
}

type unsupportedAddr string

func (a unsupportedAddr) Network() string { return "test" }

func (a unsupportedAddr) String() string { return string(a) }

func TestStartAuditEgressLoggerLogsAllowEvents(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	reader := &fakeAuditEventReader{
		results: []auditReadResult{
			{event: ebpf.EgressEvent{
				Destination: netip.MustParseAddr("203.0.113.10"),
				Reason:      ebpf.EgressReasonNotAllowed,
				Action:      ebpf.EgressActionAllow,
				Protocol:    ebpf.EgressProtocolTCP,
				Port:        443,
			}},
			{event: ebpf.EgressEvent{
				Destination: netip.MustParseAddr("203.0.113.11"),
				Reason:      ebpf.EgressReasonExpired,
				Action:      ebpf.EgressActionDrop,
			}},
		},
		closed: make(chan struct{}),
	}

	ctx, cancel := context.WithCancel(context.Background())
	stop, err := startAuditEgressLogger(ctx, logger, fakeAuditEventSource{reader: reader})
	if err != nil {
		t.Fatalf("startAuditEgressLogger() error = %v", err)
	}
	cancel()
	stop()

	output := buf.String()
	if !strings.Contains(output, "would_deny_egress") {
		t.Fatalf("log output = %q, want would_deny_egress", output)
	}
	if !strings.Contains(output, "dst=203.0.113.10") {
		t.Fatalf("log output = %q, want dst=203.0.113.10", output)
	}
	if !strings.Contains(output, "reason=not_allowed") {
		t.Fatalf("log output = %q, want reason=not_allowed", output)
	}
	if !strings.Contains(output, "proto=tcp") {
		t.Fatalf("log output = %q, want proto=tcp", output)
	}
	if !strings.Contains(output, "port=443") {
		t.Fatalf("log output = %q, want port=443", output)
	}
	if strings.Contains(output, "203.0.113.11") {
		t.Fatalf("log output = %q, want dropped event to be ignored", output)
	}
}

func TestStartAuditEgressLoggerClosesReaderOnShutdown(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	reader := &fakeAuditEventReader{closed: make(chan struct{})}

	stop, err := startAuditEgressLogger(context.Background(), logger, fakeAuditEventSource{reader: reader})
	if err != nil {
		t.Fatalf("startAuditEgressLogger() error = %v", err)
	}

	stop()

	select {
	case <-reader.closed:
	default:
		t.Fatal("reader.closed was not closed by stop()")
	}
}

func TestStartAuditEgressLoggerReturnsEventReaderError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	boom := errors.New("boom")

	_, err := startAuditEgressLogger(context.Background(), logger, fakeAuditEventSource{err: boom})
	if err == nil {
		t.Fatal("startAuditEgressLogger() error = nil, want non-nil")
	}
	if !errors.Is(err, boom) {
		t.Fatalf("startAuditEgressLogger() error = %v, want %v", err, boom)
	}
}

type fakeAuditEventSource struct {
	reader ebpf.EventReader
	err    error
}

func (s fakeAuditEventSource) EventReader() (ebpf.EventReader, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.reader, nil
}

type auditReadResult struct {
	event ebpf.EgressEvent
	err   error
}

type fakeAuditEventReader struct {
	results []auditReadResult
	closed  chan struct{}
}

func (r *fakeAuditEventReader) Read() (ebpf.EgressEvent, error) {
	if len(r.results) > 0 {
		next := r.results[0]
		r.results = r.results[1:]
		return next.event, next.err
	}

	<-r.closed
	return ebpf.EgressEvent{}, errors.New("closed")
}

func (r *fakeAuditEventReader) Close() error {
	select {
	case <-r.closed:
	default:
		close(r.closed)
	}
	return nil
}

func TestDNSListenerLifecycleStartReturnsUDPBindError(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(udp) error = %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })

	lc := &dnsListenerLifecycle{
		addr: pc.LocalAddr().String(),
		handler: dns.HandlerFunc(func(dns.ResponseWriter, *dns.Msg) {
		}),
	}

	if err := lc.Start(context.Background()); err == nil {
		t.Fatal("Start() error = nil, want non-nil (port already bound for UDP)")
	}
}

func TestDNSListenerLifecycleStartClosesUDPOnTCPBindError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen(tcp) error = %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	addr := ln.Addr().String()
	lc := &dnsListenerLifecycle{
		addr: addr,
		handler: dns.HandlerFunc(func(dns.ResponseWriter, *dns.Msg) {
		}),
	}

	if err := lc.Start(context.Background()); err == nil {
		t.Fatal("Start() error = nil, want non-nil (port already bound for TCP)")
	}

	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatalf("ListenPacket(udp) after failed Start() error = %v, want nil", err)
	}
	_ = pc.Close()
}

func TestDNSListenerLifecycleStopContinuesAfterTCPError(t *testing.T) {
	var calls []string

	lc := &dnsListenerLifecycle{
		tcp: &fakeDNSServer{
			calls:   &calls,
			name:    "tcp",
			stopErr: errors.New("boom"),
		},
		udp: &fakeDNSServer{
			calls: &calls,
			name:  "udp",
		},
	}

	if err := lc.Stop(context.Background()); err == nil {
		t.Fatal("Stop() error = nil, want non-nil")
	}
	if want := []string{"tcp:stop", "udp:stop"}; len(calls) != len(want) || calls[0] != want[0] || calls[1] != want[1] {
		t.Fatalf("Stop() calls = %v, want %v", calls, want)
	}
}

func TestDNSClientUpstreamExchange(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(udp) error = %v", err)
	}

	server := &dns.Server{
		PacketConn: pc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			resp := new(dns.Msg)
			resp.SetReply(req)
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   req.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    30,
				},
				A: net.IPv4(192, 0, 2, 55),
			})
			_ = w.WriteMsg(resp)
		}),
	}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() {
		_ = server.ShutdownContext(context.Background())
	})

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	upstream := dnsClientUpstream{
		addrs:  []string{pc.LocalAddr().String()},
		dialer: &net.Dialer{},
	}
	resp, err := upstream.Exchange(ctx, req)
	if err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("len(resp.Answer) = %d, want 1", len(resp.Answer))
	}
	record, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("resp.Answer[0] type = %T, want *dns.A", resp.Answer[0])
	}
	if got := record.A.String(); got != "192.0.2.55" {
		t.Fatalf("record.A = %s, want 192.0.2.55", got)
	}
}

func TestDNSClientUpstreamExchangeFallsBackToNextUpstream(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(udp) error = %v", err)
	}

	server := &dns.Server{
		PacketConn: pc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			resp := new(dns.Msg)
			resp.SetReply(req)
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   req.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    30,
				},
				A: net.IPv4(192, 0, 2, 99),
			})
			_ = w.WriteMsg(resp)
		}),
	}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() {
		_ = server.ShutdownContext(context.Background())
	})

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	upstream := dnsClientUpstream{
		addrs:  []string{"missing-port", pc.LocalAddr().String()},
		dialer: &net.Dialer{},
	}
	resp, err := upstream.Exchange(ctx, req)
	if err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("len(resp.Answer) = %d, want 1", len(resp.Answer))
	}
	record, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("resp.Answer[0] type = %T, want *dns.A", resp.Answer[0])
	}
	if got := record.A.String(); got != "192.0.2.99" {
		t.Fatalf("record.A = %s, want 192.0.2.99", got)
	}
}

func TestDNSClientUpstreamExchangeReturnsErrorWhenAllUpstreamsFail(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	upstream := dnsClientUpstream{
		addrs:  []string{"missing-port", "still-missing-port"},
		dialer: &net.Dialer{},
	}
	resp, err := upstream.Exchange(ctx, req)
	if err == nil {
		t.Fatal("Exchange() error = nil, want non-nil")
	}
	if resp != nil {
		t.Fatalf("resp = %#v, want nil", resp)
	}
}

type fakeDNSServer struct {
	calls    *[]string
	name     string
	stopErr  error
	startErr error
}

func (f *fakeDNSServer) ActivateAndServe() error {
	if f.calls != nil {
		*f.calls = append(*f.calls, f.name+":start")
	}
	return f.startErr
}

func (f *fakeDNSServer) ShutdownContext(context.Context) error {
	if f.calls != nil {
		*f.calls = append(*f.calls, f.name+":stop")
	}
	return f.stopErr
}

func TestBuildComponentsUsesLiveTrustReconciler(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := testConfig(t)
	manager := &fakeEBPFManager{}

	var capturedReconciler interface {
		ReconcileHost(context.Context, string, []ebpf.TrustEntry) error
	}
	builders := componentBuilders{
		newPolicy:         func([]string) (policyAllows, error) { return allowAllPolicy{}, nil },
		validateInterface: func(string) error { return nil },
		newEBPFManager: func(config.Config) (ebpfManagerLifecycle, error) {
			return manager, nil
		},
		newRedirectManager: func(config.Config) (runtime.Lifecycle, error) {
			return &fakeLifecycle{}, nil
		},
		newDNSProxy: func(cfg dnsProxyConfig) dns.Handler {
			capturedReconciler = cfg.Reconciler
			return dns.HandlerFunc(func(dns.ResponseWriter, *dns.Msg) {})
		},
		newDNSLifecycle: func(string, dns.Handler) runtime.Lifecycle {
			return &fakeLifecycle{}
		},
		newMarkedDialer: func(uint32) (*net.Dialer, error) {
			return &net.Dialer{}, nil
		},
	}

	svc, err := buildComponents(cfg, logger, builders)
	if err != nil {
		t.Fatalf("buildComponents() error = %v", err)
	}
	if svc.Trust == nil {
		t.Fatal("buildComponents() returned nil trust lifecycle")
	}
	lifecycleSync, ok := svc.Trust.(*trustsync.Service)
	if !ok {
		t.Fatalf("buildComponents() trust lifecycle type = %T, want *trustsync.Service", svc.Trust)
	}
	if capturedReconciler == nil {
		t.Fatal("buildComponents() passed nil trust reconciler")
	}
	reconcilerImpl, ok := capturedReconciler.(liveTrustReconciler)
	if !ok {
		t.Fatalf("capturedReconciler type = %T, want liveTrustReconciler", capturedReconciler)
	}
	reconcilerSync, ok := reconcilerImpl.sync.(*trustsync.Service)
	if !ok {
		t.Fatalf("live trust reconciler sync type = %T, want *trustsync.Service", reconcilerImpl.sync)
	}
	if reconcilerSync != lifecycleSync {
		t.Fatal("buildComponents() did not share trust service between reconciler and lifecycle")
	}

	entry := ebpf.TrustEntry{
		IPv4:      netip.MustParseAddr("127.0.0.1"),
		Port:      443,
		ExpiresAt: time.Now().Add(time.Minute),
	}

	first := &captureTrustWriter{}
	manager.writer = first
	if err := capturedReconciler.ReconcileHost(context.Background(), "api.github.com", []ebpf.TrustEntry{entry}); err != nil {
		t.Fatalf("capturedReconciler.ReconcileHost() with first writer error = %v", err)
	}
	if first.calls != 1 {
		t.Fatalf("first.calls = %d, want 1", first.calls)
	}

	second := &captureTrustWriter{}
	manager.writer = second
	if err := capturedReconciler.ReconcileHost(context.Background(), "api.github.com", []ebpf.TrustEntry{entry}); err != nil {
		t.Fatalf("capturedReconciler.ReconcileHost() with second writer error = %v", err)
	}
	if second.calls != 1 {
		t.Fatalf("second.calls = %d, want 1", second.calls)
	}
	if first.calls != 1 {
		t.Fatalf("first.calls after swap = %d, want 1", first.calls)
	}
}

func TestBuildComponentsLiveTrustReconcilerContinuesAfterAllowErrorAndUpdatesState(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := testConfig(t)
	manager := &fakeEBPFManager{}

	var capturedReconciler interface {
		ReconcileHost(context.Context, string, []ebpf.TrustEntry) error
	}
	builders := componentBuilders{
		newPolicy:         func([]string) (policyAllows, error) { return allowAllPolicy{}, nil },
		validateInterface: func(string) error { return nil },
		newEBPFManager: func(config.Config) (ebpfManagerLifecycle, error) {
			return manager, nil
		},
		newRedirectManager: func(config.Config) (runtime.Lifecycle, error) {
			return &fakeLifecycle{}, nil
		},
		newDNSProxy: func(cfg dnsProxyConfig) dns.Handler {
			capturedReconciler = cfg.Reconciler
			return dns.HandlerFunc(func(dns.ResponseWriter, *dns.Msg) {})
		},
		newDNSLifecycle: func(string, dns.Handler) runtime.Lifecycle {
			return &fakeLifecycle{}
		},
		newMarkedDialer: func(uint32) (*net.Dialer, error) {
			return &net.Dialer{}, nil
		},
	}

	svc, err := buildComponents(cfg, logger, builders)
	if err != nil {
		t.Fatalf("buildComponents() error = %v", err)
	}
	reconcilerImpl, ok := capturedReconciler.(liveTrustReconciler)
	if !ok {
		t.Fatalf("capturedReconciler type = %T, want liveTrustReconciler", capturedReconciler)
	}
	reconcilerSync, ok := reconcilerImpl.sync.(*trustsync.Service)
	if !ok {
		t.Fatalf("live trust reconciler sync type = %T, want *trustsync.Service", reconcilerImpl.sync)
	}
	if svc.Trust != reconcilerSync {
		t.Fatal("buildComponents() did not share trust service between reconciler and lifecycle")
	}

	boom := errors.New("allow failed")
	writer := &recordingTrustWriter{
		allowErrByKey: map[string]error{
			"127.0.0.1:443": boom,
		},
	}
	manager.writer = writer

	entries := []ebpf.TrustEntry{
		{
			IPv4:      netip.MustParseAddr("127.0.0.1"),
			Port:      443,
			ExpiresAt: time.Now().Add(time.Minute),
		},
		{
			IPv4:      netip.MustParseAddr("127.0.0.2"),
			Port:      443,
			ExpiresAt: time.Now().Add(time.Minute),
		},
	}

	err = capturedReconciler.ReconcileHost(context.Background(), "api.github.com", entries)
	if !errors.Is(err, boom) {
		t.Fatalf("capturedReconciler.ReconcileHost() error = %v, want %v", err, boom)
	}
	if writer.allowCalls != 2 {
		t.Fatalf("writer.allowCalls = %d, want 2", writer.allowCalls)
	}
	assertTrustState(t, reconcilerSync, trustsync.Destination{
		IP:       netip.MustParseAddr("127.0.0.1"),
		Port:     443,
		Protocol: trustsync.ProtocolTCP,
	}, trustsync.AggregateState{RefCount: 1})
	assertTrustState(t, reconcilerSync, trustsync.Destination{
		IP:       netip.MustParseAddr("127.0.0.2"),
		Port:     443,
		Protocol: trustsync.ProtocolTCP,
	}, trustsync.AggregateState{RefCount: 1})
}

func TestBuildComponentsTrustLifecyclePrunesWithWriterDelete(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := testConfig(t)
	manager := &fakeEBPFManager{}

	var capturedReconciler interface {
		ReconcileHost(context.Context, string, []ebpf.TrustEntry) error
	}
	builders := componentBuilders{
		newPolicy:         func([]string) (policyAllows, error) { return allowAllPolicy{}, nil },
		validateInterface: func(string) error { return nil },
		newEBPFManager: func(config.Config) (ebpfManagerLifecycle, error) {
			return manager, nil
		},
		newRedirectManager: func(config.Config) (runtime.Lifecycle, error) {
			return &fakeLifecycle{}, nil
		},
		newDNSProxy: func(cfg dnsProxyConfig) dns.Handler {
			capturedReconciler = cfg.Reconciler
			return dns.HandlerFunc(func(dns.ResponseWriter, *dns.Msg) {})
		},
		newDNSLifecycle: func(string, dns.Handler) runtime.Lifecycle {
			return &fakeLifecycle{}
		},
		newMarkedDialer: func(uint32) (*net.Dialer, error) {
			return &net.Dialer{}, nil
		},
	}

	svc, err := buildComponents(cfg, logger, builders)
	if err != nil {
		t.Fatalf("buildComponents() error = %v", err)
	}
	reconcilerImpl, ok := capturedReconciler.(liveTrustReconciler)
	if !ok {
		t.Fatalf("capturedReconciler type = %T, want liveTrustReconciler", capturedReconciler)
	}
	reconcilerSync := reconcilerImpl.sync.(*trustsync.Service)
	if svc.Trust != reconcilerSync {
		t.Fatal("buildComponents() did not share trust service between reconciler and lifecycle")
	}

	writer := &recordingTrustWriter{}
	manager.writer = writer

	dst := trustsync.Destination{
		IP:       netip.MustParseAddr("127.0.0.3"),
		Port:     443,
		Protocol: trustsync.ProtocolUDP,
	}
	reconcilerSync.ReconcileHostAnswers("api.github.com", []trustsync.Destination{dst})
	reconcilerSync.ReconcileHostAnswers("api.github.com", nil)
	pruned := reconcilerSync.PruneStale()
	if len(pruned) != 1 || pruned[0] != dst {
		t.Fatalf("PruneStale() pruned %v, want [%v]", pruned, dst)
	}
	if writer.deleteCalls != 1 {
		t.Fatalf("writer.deleteCalls = %d, want 1", writer.deleteCalls)
	}
}

func TestBuildComponentsTrustLifecycleHonorsConfiguredCleanupTiming(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := testConfig(t)
	cfg.Trust.MaxStaleHold = 120 * time.Millisecond
	cfg.Trust.SweepInterval = 10 * time.Millisecond
	manager := &fakeEBPFManager{}

	var capturedReconciler interface {
		ReconcileHost(context.Context, string, []ebpf.TrustEntry) error
	}
	builders := componentBuilders{
		newPolicy:         func([]string) (policyAllows, error) { return allowAllPolicy{}, nil },
		validateInterface: func(string) error { return nil },
		newEBPFManager: func(config.Config) (ebpfManagerLifecycle, error) {
			return manager, nil
		},
		newRedirectManager: func(config.Config) (runtime.Lifecycle, error) {
			return &fakeLifecycle{}, nil
		},
		newDNSProxy: func(cfg dnsProxyConfig) dns.Handler {
			capturedReconciler = cfg.Reconciler
			return dns.HandlerFunc(func(dns.ResponseWriter, *dns.Msg) {})
		},
		newDNSLifecycle: func(string, dns.Handler) runtime.Lifecycle {
			return &fakeLifecycle{}
		},
		newMarkedDialer: func(uint32) (*net.Dialer, error) {
			return &net.Dialer{}, nil
		},
	}

	svc, err := buildComponents(cfg, logger, builders)
	if err != nil {
		t.Fatalf("buildComponents() error = %v", err)
	}
	reconcilerImpl, ok := capturedReconciler.(liveTrustReconciler)
	if !ok {
		t.Fatalf("capturedReconciler type = %T, want liveTrustReconciler", capturedReconciler)
	}
	reconcilerSync := reconcilerImpl.sync.(*trustsync.Service)
	if svc.Trust != reconcilerSync {
		t.Fatal("buildComponents() did not share trust service between reconciler and lifecycle")
	}

	writer := &recordingTrustWriter{}
	manager.writer = writer

	dst := trustsync.Destination{
		IP:       netip.MustParseAddr("127.0.0.4"),
		Port:     443,
		Protocol: trustsync.ProtocolUDP,
	}
	reconcilerSync.ReconcileHostAnswers("api.github.com", []trustsync.Destination{dst})
	reconcilerSync.ReconcileHostAnswers("api.github.com", nil)

	if err := svc.Trust.Start(context.Background()); err != nil {
		t.Fatalf("svc.Trust.Start() error = %v", err)
	}
	defer func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := svc.Trust.Stop(stopCtx); err != nil {
			t.Fatalf("svc.Trust.Stop() error = %v", err)
		}
	}()

	time.Sleep(cfg.Trust.MaxStaleHold / 2)
	if _, ok := reconcilerSync.State(dst); !ok {
		t.Fatal("destination pruned before max stale hold elapsed")
	}

	waitForCalls(t, func() bool {
		_, ok := reconcilerSync.State(dst)
		return !ok
	})

	if writer.deleteCalls != 1 {
		t.Fatalf("writer.deleteCalls = %d, want 1", writer.deleteCalls)
	}
}

func TestBuildComponentsTrustLifecycleRefreshesRetainedStaleDestinationThroughWriter(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := testConfig(t)
	cfg.Trust.MaxStaleHold = time.Minute
	cfg.Trust.SweepInterval = 50 * time.Millisecond
	manager := &fakeEBPFManager{}

	var capturedReconciler interface {
		ReconcileHost(context.Context, string, []ebpf.TrustEntry) error
	}
	builders := componentBuilders{
		newPolicy:         func([]string) (policyAllows, error) { return allowAllPolicy{}, nil },
		validateInterface: func(string) error { return nil },
		newEBPFManager: func(config.Config) (ebpfManagerLifecycle, error) {
			return manager, nil
		},
		newRedirectManager: func(config.Config) (runtime.Lifecycle, error) {
			return &fakeLifecycle{}, nil
		},
		newDNSProxy: func(cfg dnsProxyConfig) dns.Handler {
			capturedReconciler = cfg.Reconciler
			return dns.HandlerFunc(func(dns.ResponseWriter, *dns.Msg) {})
		},
		newDNSLifecycle: func(string, dns.Handler) runtime.Lifecycle {
			return &fakeLifecycle{}
		},
		newMarkedDialer: func(uint32) (*net.Dialer, error) {
			return &net.Dialer{}, nil
		},
	}

	svc, err := buildComponents(cfg, logger, builders)
	if err != nil {
		t.Fatalf("buildComponents() error = %v", err)
	}
	reconcilerImpl, ok := capturedReconciler.(liveTrustReconciler)
	if !ok {
		t.Fatalf("capturedReconciler type = %T, want liveTrustReconciler", capturedReconciler)
	}
	reconcilerSync := reconcilerImpl.sync.(*trustsync.Service)
	if svc.Trust != reconcilerSync {
		t.Fatal("buildComponents() did not share trust service between reconciler and lifecycle")
	}

	writer := &recordingTrustWriter{}
	manager.writer = writer

	dst := trustsync.Destination{
		IP:       netip.MustParseAddr("127.0.0.5"),
		Port:     443,
		Protocol: trustsync.ProtocolUDP,
	}
	reconcilerSync.ReconcileHostAnswers("api.github.com", []trustsync.Destination{dst})
	reconcilerSync.ReconcileHostAnswers("api.github.com", nil)

	if writer.allowCalls != 1 {
		t.Fatalf("writer.allowCalls = %d, want 1 refresh allow call", writer.allowCalls)
	}
	entry := writer.lastAllowedEntry
	if entry.IPv4 != dst.IP || entry.Port != dst.Port {
		t.Fatalf("writer.lastAllowedEntry = %+v, want dst %v", entry, dst)
	}
	if !entry.ExpiresAt.After(time.Now()) {
		t.Fatalf("writer.lastAllowedEntry.ExpiresAt = %v, want future time", entry.ExpiresAt)
	}
}

func TestDNSProxyConfigDoesNotExposeDirectTrustWriter(t *testing.T) {
	if _, ok := reflect.TypeOf(dnsProxyConfig{}).FieldByName("Trust"); ok {
		t.Fatal("dnsProxyConfig unexpectedly exposes Trust writer field")
	}
}

func TestBuildRuntimeServiceRequiresMarkedDialer(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := testConfig(t)
	boom := errors.New("marked dialer unavailable")

	_, _, err := buildRuntimeService(cfg, logger, componentBuilders{
		validateInterface: func(string) error { return nil },
		newMarkedDialer: func(mark uint32) (*net.Dialer, error) {
			if mark != uint32(cfg.DNS.Mark) {
				t.Fatalf("newMarkedDialer() mark = %d, want %d", mark, cfg.DNS.Mark)
			}
			return nil, boom
		},
	})
	if err == nil {
		t.Fatal("buildRuntimeService() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "build marked dialer") {
		t.Fatalf("buildRuntimeService() error = %q, want marked dialer context", err)
	}
	if !strings.Contains(err.Error(), boom.Error()) {
		t.Fatalf("buildRuntimeService() error = %q, want wrapped %q", err, boom.Error())
	}
}

func TestBuildRuntimeServiceFailsClosedOnIPv6Interface(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := testConfig(t)
	boom := errors.New("interface eth0 has IPv6 addresses assigned")

	_, _, err := buildRuntimeService(cfg, logger, componentBuilders{
		validateInterface: func(iface string) error {
			if iface != cfg.Interface.Name {
				t.Fatalf("validateInterface() iface = %q, want %q", iface, cfg.Interface.Name)
			}
			return boom
		},
	})
	if err == nil {
		t.Fatal("buildRuntimeService() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "validate protected interface") {
		t.Fatalf("buildRuntimeService() error = %q, want interface validation context", err)
	}
	if !strings.Contains(err.Error(), boom.Error()) {
		t.Fatalf("buildRuntimeService() error = %q, want wrapped %q", err, boom.Error())
	}
}

func TestBuildRuntimeServiceUsesResolvedInterface(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := testConfig(t)
	cfg.Interface = config.InterfaceSelector{Mode: "auto"}

	_, _, err := buildRuntimeService(cfg, logger, componentBuilders{
		resolveConfig: func(config.Config) (resolvedRuntimeConfig, error) {
			return resolvedRuntimeConfig{
				Interface: "ens5",
				Upstreams: []string{"1.1.1.1:53"},
			}, nil
		},
		validateInterface: func(iface string) error {
			if iface != "ens5" {
				t.Fatalf("validateInterface() iface = %q, want %q", iface, "ens5")
			}
			return errors.New("boom")
		},
	})
	if err == nil {
		t.Fatal("buildRuntimeService() error = nil, want non-nil")
	}
}

func TestBuildRuntimeServiceUsesResolvedDNSUpstreams(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := testConfig(t)
	cfg.DNS.Upstreams = config.UpstreamSelector{Mode: "auto"}

	var captured dnsClientUpstream
	_, _, err := buildRuntimeService(cfg, logger, componentBuilders{
		resolveConfig: func(config.Config) (resolvedRuntimeConfig, error) {
			return resolvedRuntimeConfig{
				Interface: "eth0",
				Upstreams: []string{"1.1.1.1:53", "9.9.9.9:53"},
			}, nil
		},
		newPolicy:         func([]string) (policyAllows, error) { return allowAllPolicy{}, nil },
		validateInterface: func(string) error { return nil },
		newEBPFManager: func(config.Config) (ebpfManagerLifecycle, error) {
			return &fakeEBPFManager{writer: &captureTrustWriter{}}, nil
		},
		newRedirectManager: func(config.Config) (runtime.Lifecycle, error) {
			return &fakeLifecycle{}, nil
		},
		newDNSProxy: func(cfg dnsProxyConfig) dns.Handler {
			upstream, ok := cfg.Upstream.(dnsClientUpstream)
			if !ok {
				t.Fatalf("cfg.Upstream type = %T, want dnsClientUpstream", cfg.Upstream)
			}
			captured = upstream
			return dns.HandlerFunc(func(dns.ResponseWriter, *dns.Msg) {})
		},
		newDNSLifecycle: func(string, dns.Handler) runtime.Lifecycle {
			return &fakeLifecycle{}
		},
		newMarkedDialer: func(uint32) (*net.Dialer, error) {
			return &net.Dialer{}, nil
		},
	})
	if err != nil {
		t.Fatalf("buildRuntimeService() error = %v", err)
	}
	if got, want := captured.addrs, []string{"1.1.1.1:53", "9.9.9.9:53"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("captured.addrs = %v, want %v", got, want)
	}
}

func TestBuildRuntimeServiceWrapsRedirectManagerError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := testConfig(t)
	boom := errors.New("redirect constructor boom")

	_, _, err := buildRuntimeService(cfg, logger, componentBuilders{
		newPolicy:         func([]string) (policyAllows, error) { return allowAllPolicy{}, nil },
		validateInterface: func(string) error { return nil },
		newEBPFManager: func(config.Config) (ebpfManagerLifecycle, error) {
			return &fakeEBPFManager{}, nil
		},
		newRedirectManager: func(config.Config) (runtime.Lifecycle, error) {
			return nil, boom
		},
		newDNSProxy: func(dnsProxyConfig) dns.Handler {
			t.Fatal("newDNSProxy should not be called")
			return nil
		},
		newDNSLifecycle: func(string, dns.Handler) runtime.Lifecycle {
			t.Fatal("newDNSLifecycle should not be called")
			return nil
		},
		newMarkedDialer: func(uint32) (*net.Dialer, error) {
			return &net.Dialer{}, nil
		},
	})
	if err == nil {
		t.Fatal("buildRuntimeService() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "build redirect manager") {
		t.Fatalf("buildRuntimeService() error = %q, want redirect manager context", err)
	}
	if !strings.Contains(err.Error(), boom.Error()) {
		t.Fatalf("buildRuntimeService() error = %q, want wrapped %q", err, boom.Error())
	}
}

func TestBuildRuntimeServiceSkipsHTTPSLifecycleWhenHTTPSDisabled(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := testConfig(t)
	cfg.HTTPS = config.HTTPS{}

	var trustPorts []uint16
	svc, _, err := buildRuntimeService(cfg, logger, componentBuilders{
		newPolicy:         func([]string) (policyAllows, error) { return allowAllPolicy{}, nil },
		validateInterface: func(string) error { return nil },
		newEBPFManager: func(config.Config) (ebpfManagerLifecycle, error) {
			return &fakeEBPFManager{writer: &captureTrustWriter{}}, nil
		},
		newRedirectManager: func(cfg config.Config) (runtime.Lifecycle, error) {
			if cfg.HTTPS.Configured() {
				t.Fatal("redirect manager received configured HTTPS block, want disabled HTTPS")
			}
			return &fakeLifecycle{}, nil
		},
		newDNSProxy: func(cfg dnsProxyConfig) dns.Handler {
			ports, ok := cfg.TrustPlan.PortsForHost("example.com")
			if !ok {
				t.Fatal("TrustPlan.PortsForHost(example.com) = _, false, want true")
			}
			trustPorts = append([]uint16(nil), ports...)
			return dns.HandlerFunc(func(dns.ResponseWriter, *dns.Msg) {})
		},
		newDNSLifecycle: func(string, dns.Handler) runtime.Lifecycle {
			return &fakeLifecycle{}
		},
		newMarkedDialer: func(uint32) (*net.Dialer, error) {
			return &net.Dialer{}, nil
		},
	})
	if err != nil {
		t.Fatalf("buildRuntimeService() error = %v", err)
	}
	if svc.HTTPS != nil {
		t.Fatalf("svc.HTTPS = %#v, want nil when HTTPS is disabled", svc.HTTPS)
	}
	if got, want := trustPorts, []uint16{443, 8443}; !reflect.DeepEqual(got, want) {
		t.Fatalf("trustPorts = %v, want %v", got, want)
	}
}

func TestRunStopsServiceOnContextCancellation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := testConfig(t)
	cfg.HTTPS.Listen = "127.0.0.1:0"

	redirectLC := &fakeLifecycle{}
	dnsLC := &fakeLifecycle{}
	manager := &fakeEBPFManager{writer: &captureTrustWriter{}}

	builders := componentBuilders{
		newPolicy:         func([]string) (policyAllows, error) { return allowAllPolicy{}, nil },
		validateInterface: func(string) error { return nil },
		newEBPFManager: func(config.Config) (ebpfManagerLifecycle, error) {
			return manager, nil
		},
		newRedirectManager: func(config.Config) (runtime.Lifecycle, error) {
			return redirectLC, nil
		},
		newDNSProxy: func(dnsProxyConfig) dns.Handler {
			return dns.HandlerFunc(func(dns.ResponseWriter, *dns.Msg) {})
		},
		newDNSLifecycle: func(string, dns.Handler) runtime.Lifecycle {
			return dnsLC
		},
		newMarkedDialer: func(uint32) (*net.Dialer, error) {
			return &net.Dialer{}, nil
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, cfg, logger, builders, func() (context.Context, context.CancelFunc) {
			return context.WithCancel(context.Background())
		})
	}()

	waitForCalls(t, func() bool { return manager.startCalls == 1 && redirectLC.startCalls == 1 })
	cancel()

	if err := <-done; err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if redirectLC.stopCalls != 1 {
		t.Fatalf("redirectLC.stopCalls = %d, want 1", redirectLC.stopCalls)
	}
	if dnsLC.stopCalls != 1 {
		t.Fatalf("dnsLC.stopCalls = %d, want 1", dnsLC.stopCalls)
	}
	if manager.stopCalls != 1 {
		t.Fatalf("manager.stopCalls = %d, want 1", manager.stopCalls)
	}
}

func TestRunStartsAuditLoggerOnlyInAuditMode(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := testConfig(t)
	cfg.Mode = config.ModeEnforce
	cfg.HTTPS.Listen = "127.0.0.1:0"

	manager := &fakeEBPFManager{
		writer:         &captureTrustWriter{},
		eventReaderErr: errors.New("event reader should not be requested in enforce mode"),
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, cfg, logger, componentBuilders{
			newPolicy:         func([]string) (policyAllows, error) { return allowAllPolicy{}, nil },
			validateInterface: func(string) error { return nil },
			newEBPFManager: func(config.Config) (ebpfManagerLifecycle, error) {
				return manager, nil
			},
			newRedirectManager: func(config.Config) (runtime.Lifecycle, error) {
				return &fakeLifecycle{}, nil
			},
			newDNSProxy: func(dnsProxyConfig) dns.Handler {
				return dns.HandlerFunc(func(dns.ResponseWriter, *dns.Msg) {})
			},
			newDNSLifecycle: func(string, dns.Handler) runtime.Lifecycle {
				return &fakeLifecycle{}
			},
			newMarkedDialer: func(uint32) (*net.Dialer, error) {
				return &net.Dialer{}, nil
			},
		}, func() (context.Context, context.CancelFunc) {
			return context.WithCancel(context.Background())
		})
	}()

	waitForCalls(t, func() bool { return manager.startCalls == 1 })
	cancel()

	if err := <-done; err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if manager.eventReaderCalls != 0 {
		t.Fatalf("manager.eventReaderCalls = %d, want 0", manager.eventReaderCalls)
	}
}

func TestRunAuditLoggerStartupFailureRollsBackLifecycle(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := testConfig(t)
	cfg.Mode = config.ModeAudit
	cfg.HTTPS.Listen = "127.0.0.1:0"

	redirectLC := &fakeLifecycle{}
	dnsLC := &fakeLifecycle{}
	manager := &fakeEBPFManager{
		writer:         &captureTrustWriter{},
		eventReaderErr: errors.New("reader boom"),
	}

	err := run(context.Background(), cfg, logger, componentBuilders{
		newPolicy:         func([]string) (policyAllows, error) { return allowAllPolicy{}, nil },
		validateInterface: func(string) error { return nil },
		newEBPFManager: func(config.Config) (ebpfManagerLifecycle, error) {
			return manager, nil
		},
		newRedirectManager: func(config.Config) (runtime.Lifecycle, error) {
			return redirectLC, nil
		},
		newDNSProxy: func(dnsProxyConfig) dns.Handler {
			return dns.HandlerFunc(func(dns.ResponseWriter, *dns.Msg) {})
		},
		newDNSLifecycle: func(string, dns.Handler) runtime.Lifecycle {
			return dnsLC
		},
		newMarkedDialer: func(uint32) (*net.Dialer, error) {
			return &net.Dialer{}, nil
		},
	}, func() (context.Context, context.CancelFunc) {
		return context.WithCancel(context.Background())
	})
	if err == nil {
		t.Fatal("run() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "start egress event logger") {
		t.Fatalf("run() error = %q, want audit logger context", err)
	}
	if redirectLC.stopCalls != 1 {
		t.Fatalf("redirectLC.stopCalls = %d, want 1", redirectLC.stopCalls)
	}
	if dnsLC.stopCalls != 1 {
		t.Fatalf("dnsLC.stopCalls = %d, want 1", dnsLC.stopCalls)
	}
	if manager.stopCalls != 1 {
		t.Fatalf("manager.stopCalls = %d, want 1", manager.stopCalls)
	}
}

func TestRunUsesStopContextOnShutdown(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := testConfig(t)
	cfg.HTTPS.Listen = "127.0.0.1:0"

	redirectLC := &fakeLifecycle{}
	manager := &fakeEBPFManager{writer: &captureTrustWriter{}}

	var stopCtx context.Context
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, cfg, logger, componentBuilders{
			newPolicy:         func([]string) (policyAllows, error) { return allowAllPolicy{}, nil },
			validateInterface: func(string) error { return nil },
			newEBPFManager: func(config.Config) (ebpfManagerLifecycle, error) {
				return manager, nil
			},
			newRedirectManager: func(config.Config) (runtime.Lifecycle, error) {
				return redirectLC, nil
			},
			newDNSProxy: func(dnsProxyConfig) dns.Handler {
				return dns.HandlerFunc(func(dns.ResponseWriter, *dns.Msg) {})
			},
			newDNSLifecycle: func(string, dns.Handler) runtime.Lifecycle {
				return &fakeLifecycle{}
			},
			newMarkedDialer: func(uint32) (*net.Dialer, error) {
				return &net.Dialer{}, nil
			},
		}, func() (context.Context, context.CancelFunc) {
			var cancel context.CancelFunc
			stopCtx, cancel = context.WithCancel(context.Background())
			return stopCtx, cancel
		})
	}()

	waitForCalls(t, func() bool { return manager.startCalls == 1 })
	cancel()

	if err := <-done; err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if len(redirectLC.stopCtxs) != 1 {
		t.Fatalf("len(redirectLC.stopCtxs) = %d, want 1", len(redirectLC.stopCtxs))
	}
	if redirectLC.stopCtxs[0] != stopCtx {
		t.Fatal("run() did not pass the stop context returned by newStopContext")
	}
}

type fakeEBPFManager struct {
	startErr error
	stopErr  error

	writer         ebpf.TrustWriter
	trustWriterErr error
	reader         ebpf.EventReader
	eventReaderErr error

	startCalls       int
	stopCalls        int
	eventReaderCalls int
	stopCtxs         []context.Context
}

func (f *fakeEBPFManager) Start(context.Context) error {
	f.startCalls++
	return f.startErr
}

func (f *fakeEBPFManager) Stop(ctx context.Context) error {
	f.stopCalls++
	f.stopCtxs = append(f.stopCtxs, ctx)
	return f.stopErr
}

func (f *fakeEBPFManager) TrustWriter() (ebpf.TrustWriter, error) {
	if f.trustWriterErr != nil {
		return nil, f.trustWriterErr
	}
	if f.writer == nil {
		return nil, ebpf.ErrManagerNotStarted
	}
	return f.writer, nil
}

func (f *fakeEBPFManager) EventReader() (ebpf.EventReader, error) {
	f.eventReaderCalls++
	if f.eventReaderErr != nil {
		return nil, f.eventReaderErr
	}
	if f.reader == nil {
		return nil, ebpf.ErrManagerNotStarted
	}
	return f.reader, nil
}

type captureTrustWriter struct {
	calls int
}

func (c *captureTrustWriter) Allow(context.Context, ebpf.TrustEntry) error {
	c.calls++
	return nil
}

type recordingTrustWriter struct {
	allowCalls       int
	deleteCalls      int
	lastAllowedEntry ebpf.TrustEntry
	allowErrByKey    map[string]error
	deleteErrByKey   map[string]error
}

func (w *recordingTrustWriter) Allow(_ context.Context, entry ebpf.TrustEntry) error {
	w.allowCalls++
	w.lastAllowedEntry = entry
	if err := w.allowErrByKey[trustEntryKey(entry)]; err != nil {
		return err
	}
	return nil
}

func (w *recordingTrustWriter) Delete(_ context.Context, ipv4 netip.Addr, port uint16) error {
	w.deleteCalls++
	if err := w.deleteErrByKey[trustDestinationKey(ipv4, port)]; err != nil {
		return err
	}
	return nil
}

func trustEntryKey(entry ebpf.TrustEntry) string {
	return trustDestinationKey(entry.IPv4, entry.Port)
}

func trustDestinationKey(ip netip.Addr, port uint16) string {
	return ip.String() + ":" + strconv.Itoa(int(port))
}

func assertTrustState(t *testing.T, svc *trustsync.Service, dst trustsync.Destination, want trustsync.AggregateState) {
	t.Helper()
	got, ok := svc.State(dst)
	if !ok {
		t.Fatalf("State(%v) missing", dst)
	}
	if got.RefCount != want.RefCount {
		t.Fatalf("State(%v).RefCount = %d, want %d", dst, got.RefCount, want.RefCount)
	}
	if got.Stale != want.Stale {
		t.Fatalf("State(%v).Stale = %v, want %v", dst, got.Stale, want.Stale)
	}
}

type allowAllPolicy struct{}

func (allowAllPolicy) Allows(string) bool { return true }

type fakeLifecycle struct {
	startErr error
	stopErr  error

	startCalls int
	stopCalls  int
	stopCtxs   []context.Context
}

func (f *fakeLifecycle) Start(context.Context) error {
	f.startCalls++
	return f.startErr
}

func (f *fakeLifecycle) Stop(ctx context.Context) error {
	f.stopCalls++
	f.stopCtxs = append(f.stopCtxs, ctx)
	return f.stopErr
}

func testConfig(t *testing.T) config.Config {
	t.Helper()

	caDir := t.TempDir()
	return config.Config{
		Mode: config.ModeEnforce,
		Interface: config.InterfaceSelector{
			Mode: "explicit",
			Name: "eth0",
		},
		DNS: config.DNS{
			Listen: "127.0.0.1:5353",
			Upstreams: config.UpstreamSelector{
				Mode:      "explicit",
				Addresses: []string{"1.1.1.1:53"},
			},
			Mark: 1234,
		},
		Policy: config.Policy{
			Default: "deny",
			Allow:   []string{"example.com"},
		},
		HTTPS: config.HTTPS{
			Listen: "127.0.0.1:9443",
			Ports:  []int{443},
			SNI: config.HTTPSSNI{
				Missing: "deny",
			},
			CA: config.HTTPSCA{
				CertFile: filepath.Join(caDir, "nie-test-ca.crt"),
				KeyFile:  filepath.Join(caDir, "nie-test-ca.key"),
			},
			MITM: config.HTTPSMITM{
				Default: "deny",
				Rules: []config.HTTPSMITMRule{
					{
						Host:    "example.com",
						Port:    443,
						Methods: []string{"GET"},
						Paths:   []string{"/"},
						Action:  "allow",
					},
				},
			},
		},
	}
}

func waitForCalls(t *testing.T, ready func() bool) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if ready() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met before timeout")
}
