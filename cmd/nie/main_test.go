package main

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/miekg/dns"
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
