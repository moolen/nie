package main

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestFormatProbeResult(t *testing.T) {
	line := formatProbeResult(probeResult{
		Kind:   "tcp",
		Phase:  "direct",
		Target: "192.168.56.1:18080",
		Result: "success",
	})

	want := "kind=tcp phase=direct target=192.168.56.1:18080 result=success"
	if line != want {
		t.Fatalf("line = %q, want %q", line, want)
	}
}

func TestDNSProbeSuccessWithEmptyAnswer(t *testing.T) {
	addr := startDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Rcode = dns.RcodeSuccess
		if err := w.WriteMsg(msg); err != nil {
			t.Fatalf("write msg: %v", err)
		}
	})

	result := dnsProbe(addr, "example.test", 500*time.Millisecond)
	if result != "success" {
		t.Fatalf("result = %q, want %q", result, "success")
	}
}

func TestNormalizeAddrIPv6WithoutPort(t *testing.T) {
	got := normalizeAddr("2001:db8::1", "53")
	want := "[2001:db8::1]:53"
	if got != want {
		t.Fatalf("normalizeAddr = %q, want %q", got, want)
	}
}

func TestTCPExchangeProbeSuccess(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, len(probePayload))
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		_, _ = conn.Write(buf)
	}()

	if got := tcpExchangeProbe(ln.Addr().String(), 500*time.Millisecond); got != "success" {
		t.Fatalf("tcpExchangeProbe() = %q, want %q", got, "success")
	}
}

func TestUDPExchangeProbeSuccess(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer pc.Close()

	go func() {
		buf := make([]byte, len(probePayload))
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		_, _ = pc.WriteTo(buf[:n], addr)
	}()

	if got := udpExchangeProbe(pc.LocalAddr().String(), 500*time.Millisecond); got != "success" {
		t.Fatalf("udpExchangeProbe() = %q, want %q", got, "success")
	}
}

func TestICMPProbeUsesInjectedRunner(t *testing.T) {
	prev := runICMPCommand
	defer func() { runICMPCommand = prev }()

	var gotTarget string
	var gotTimeout time.Duration
	runICMPCommand = func(_ context.Context, target string, timeout time.Duration) error {
		gotTarget = target
		gotTimeout = timeout
		return nil
	}

	if got := icmpProbe("203.0.113.10", 750*time.Millisecond); got != "success" {
		t.Fatalf("icmpProbe() = %q, want %q", got, "success")
	}
	if gotTarget != "203.0.113.10" {
		t.Fatalf("target = %q, want %q", gotTarget, "203.0.113.10")
	}
	if gotTimeout != 750*time.Millisecond {
		t.Fatalf("timeout = %v, want %v", gotTimeout, 750*time.Millisecond)
	}
}

func startDNSServer(t *testing.T, handler dns.HandlerFunc) string {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen packet: %v", err)
	}

	server := &dns.Server{
		PacketConn: pc,
		Handler:    handler,
	}
	go func() {
		_ = server.ActivateAndServe()
	}()
	t.Cleanup(func() {
		_ = server.Shutdown()
		_ = pc.Close()
	})

	return pc.LocalAddr().String()
}
