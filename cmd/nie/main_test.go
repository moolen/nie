package main

import (
	"context"
	"net"
	"testing"

	"github.com/miekg/dns"
)

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

