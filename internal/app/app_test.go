package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/moolen/nie/internal/config"
	"github.com/moolen/nie/internal/ebpf"
	"github.com/moolen/nie/internal/runtime"
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
		addr:   pc.LocalAddr().String(),
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

	if _, err := buildComponents(cfg, logger, builders); err != nil {
		t.Fatalf("buildComponents() error = %v", err)
	}
	if capturedReconciler == nil {
		t.Fatal("buildComponents() passed nil trust reconciler")
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
			if iface != cfg.Interface {
				t.Fatalf("validateInterface() iface = %q, want %q", iface, cfg.Interface)
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
		Mode:      config.ModeEnforce,
		Interface: "eth0",
		DNS: config.DNS{
			Listen:    "127.0.0.1:5353",
			Upstreams: []string{"1.1.1.1:53"},
			Mark:      1234,
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
