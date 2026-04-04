package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/moolen/nie/internal/config"
	"github.com/moolen/nie/internal/ebpf"
	"github.com/moolen/nie/internal/runtime"
)

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

func TestDNSListenerLifecycleStartReturnsUDPBindError(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket(udp) error = %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })

	lc := &dnsListenerLifecycle{
		addr: pc.LocalAddr().String(),
		handler: dns.HandlerFunc(func(dns.ResponseWriter, *dns.Msg) {
			// noop
		}),
	}

	if err := lc.Start(context.Background()); err == nil {
		t.Fatalf("Start() error = nil, want non-nil (port already bound for UDP)")
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
			// noop
		}),
	}

	if err := lc.Start(context.Background()); err == nil {
		t.Fatalf("Start() error = nil, want non-nil (port already bound for TCP)")
	}

	// If Start() partially bound UDP before failing TCP, it must have cleaned up
	// the UDP bind before returning.
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatalf("ListenPacket(udp) after failed Start() error = %v, want nil (leaked UDP bind?)", err)
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
		t.Fatalf("Stop() error = nil, want non-nil")
	}
	if want := []string{"tcp:stop", "udp:stop"}; len(calls) != len(want) || calls[0] != want[0] || calls[1] != want[1] {
		t.Fatalf("Stop() calls = %v, want %v", calls, want)
	}
}

func TestBuildComponentsUsesLiveTrustWriter(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := testConfig()
	manager := &fakeEBPFManager{}

	var capturedTrust ebpf.TrustWriter
	builders := componentBuilders{
		newPolicy: func([]string) (policyAllows, error) { return allowAllPolicy{}, nil },
		newEBPFManager: func(config.Config) (ebpfManagerLifecycle, error) {
			return manager, nil
		},
		newRedirectManager: func(config.Config) (runtime.Lifecycle, error) {
			return fakeLifecycle{}, nil
		},
		newDNSProxy: func(cfg dnsProxyConfig) dns.Handler {
			capturedTrust = cfg.Trust
			return dns.HandlerFunc(func(dns.ResponseWriter, *dns.Msg) {})
		},
		newDNSLifecycle: func(string, dns.Handler) runtime.Lifecycle {
			return fakeLifecycle{}
		},
	}

	if _, err := buildComponents(cfg, logger, builders); err != nil {
		t.Fatalf("buildComponents() error = %v", err)
	}
	if capturedTrust == nil {
		t.Fatalf("buildComponents() passed nil trust writer")
	}

	entry := ebpf.TrustEntry{
		IPv4:      netip.MustParseAddr("127.0.0.1"),
		ExpiresAt: time.Now().Add(time.Minute),
	}

	first := &captureTrustWriter{}
	manager.writer = first
	if err := capturedTrust.Allow(context.Background(), entry); err != nil {
		t.Fatalf("capturedTrust.Allow() with first writer error = %v", err)
	}
	if first.calls != 1 {
		t.Fatalf("first calls = %d, want 1", first.calls)
	}

	second := &captureTrustWriter{}
	manager.writer = second
	if err := capturedTrust.Allow(context.Background(), entry); err != nil {
		t.Fatalf("capturedTrust.Allow() with second writer error = %v", err)
	}
	if second.calls != 1 {
		t.Fatalf("second calls = %d, want 1", second.calls)
	}
	if first.calls != 1 {
		t.Fatalf("first calls after swap = %d, want 1", first.calls)
	}
}

func TestMainStartFailsWhenRedirectManagerCreationFails(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := testConfig()
	boom := errors.New("redirect constructor boom")

	builders := componentBuilders{
		newPolicy: func([]string) (policyAllows, error) { return allowAllPolicy{}, nil },
		newEBPFManager: func(config.Config) (ebpfManagerLifecycle, error) {
			return &fakeEBPFManager{}, nil
		},
		newRedirectManager: func(config.Config) (runtime.Lifecycle, error) {
			return nil, boom
		},
		newDNSProxy: func(dnsProxyConfig) dns.Handler {
			t.Fatalf("newDNSProxy should not be called")
			return nil
		},
		newDNSLifecycle: func(string, dns.Handler) runtime.Lifecycle {
			t.Fatalf("newDNSLifecycle should not be called")
			return nil
		},
	}

	err := run(context.Background(), cfg, logger, builders, func() (context.Context, context.CancelFunc) {
		return context.WithCancel(context.Background())
	})
	if err == nil {
		t.Fatalf("run() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "build redirect manager") {
		t.Fatalf("run() error = %q, want to contain %q", err, "build redirect manager")
	}
	if !strings.Contains(err.Error(), boom.Error()) {
		t.Fatalf("run() error = %q, want to contain %q", err, boom.Error())
	}
}

func TestBuildRuntimeService_RequiresMarkedDialer(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := testConfig()
	boom := errors.New("marked dialer unavailable")

	_, _, err := buildRuntimeService(cfg, logger, componentBuilders{
		newMarkedDialer: func(mark uint32) (*net.Dialer, error) {
			if mark != uint32(cfg.DNS.Mark) {
				t.Fatalf("newMarkedDialer() mark = %d, want %d", mark, cfg.DNS.Mark)
			}
			return nil, boom
		},
	})
	if err == nil {
		t.Fatalf("buildRuntimeService() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "marked dialer") {
		t.Fatalf("buildRuntimeService() error = %q, want marked dialer context", err)
	}
	if !strings.Contains(err.Error(), boom.Error()) {
		t.Fatalf("buildRuntimeService() error = %q, want wrapped %q", err, boom.Error())
	}
}

func TestStartAuditEgressLoggerLogsAllowEvents(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	reader := &fakeAuditEventReader{
		results: []auditReadResult{
			{event: ebpf.EgressEvent{
				Destination: netip.MustParseAddr("203.0.113.10"),
				Reason:      ebpf.EgressReasonNotAllowed,
				Action:      ebpf.EgressActionAllow,
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
	defer cancel()

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
	if strings.Contains(output, "203.0.113.11") {
		t.Fatalf("log output = %q, want dropped event to be ignored", output)
	}
}

type fakeEBPFManager struct {
	startErr error
	stopErr  error
	writer   ebpf.TrustWriter
	reader   ebpf.EventReader
}

func (f *fakeEBPFManager) Start(context.Context) error { return f.startErr }
func (f *fakeEBPFManager) Stop(context.Context) error  { return f.stopErr }
func (f *fakeEBPFManager) TrustWriter() (ebpf.TrustWriter, error) {
	if f.writer == nil {
		return nil, ebpf.ErrManagerNotStarted
	}
	return f.writer, nil
}
func (f *fakeEBPFManager) EventReader() (ebpf.EventReader, error) {
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

type fakeLifecycle struct{}

func (fakeLifecycle) Start(context.Context) error { return nil }
func (fakeLifecycle) Stop(context.Context) error  { return nil }

type fakeAuditEventSource struct {
	reader ebpf.EventReader
}

func (s fakeAuditEventSource) EventReader() (ebpf.EventReader, error) {
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

func testConfig() config.Config {
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
				CertFile: "/tmp/nie-test-ca.crt",
				KeyFile:  "/tmp/nie-test-ca.key",
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
