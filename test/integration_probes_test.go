//go:build integration

package test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const (
	integrationProbePayload = "nie-probe"
	fixtureTCPEchoPort      = 18081
	fixtureUDPEchoPort      = 18082
)

type integrationFixture struct {
	IP          string
	HTTPAddress string
}

func startIntegrationFixture(t *testing.T, ip string) integrationFixture {
	t.Helper()

	cert := generateFixtureCertificate(t, ip)
	httpLn := mustListenTCP(t, net.JoinHostPort(ip, "18080"))
	tcpLn := mustListenTCP(t, fixtureTCPEchoAddr(ip))
	udpPC := mustListenUDP(t, fixtureUDPEchoAddr(ip))
	https443Ln := mustListenTCP(t, net.JoinHostPort(ip, "443"))
	https8443Ln := mustListenTCP(t, net.JoinHostPort(ip, "8443"))

	httpMux := http.NewServeMux()
	httpMux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok\n")
	})

	httpServer := &http.Server{Handler: httpMux}
	httpsServer443 := &http.Server{
		Handler:   httpMux,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
	}
	httpsServer8443 := &http.Server{
		Handler:   httpMux,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
	}

	go func() { _ = httpServer.Serve(httpLn) }()
	go serveTCPEcho(tcpLn)
	go serveUDPEcho(udpPC)
	go func() { _ = httpsServer443.ServeTLS(https443Ln, "", "") }()
	go func() { _ = httpsServer8443.ServeTLS(https8443Ln, "", "") }()

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(ctx)
		_ = httpsServer443.Shutdown(ctx)
		_ = httpsServer8443.Shutdown(ctx)
		_ = httpLn.Close()
		_ = tcpLn.Close()
		_ = udpPC.Close()
		_ = https443Ln.Close()
		_ = https8443Ln.Close()
	})

	return integrationFixture{
		IP:          ip,
		HTTPAddress: httpLn.Addr().String(),
	}
}

func mustListenTCP(t *testing.T, addr string) net.Listener {
	t.Helper()

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listen tcp %s: %v", addr, err)
	}
	return ln
}

func mustListenUDP(t *testing.T, addr string) net.PacketConn {
	t.Helper()

	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatalf("listen udp %s: %v", addr, err)
	}
	return pc
}

func serveTCPEcho(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func(conn net.Conn) {
			defer conn.Close()
			buf := make([]byte, len(integrationProbePayload))
			for {
				if _, err := io.ReadFull(conn, buf); err != nil {
					return
				}
				if _, err := conn.Write(buf); err != nil {
					return
				}
			}
		}(conn)
	}
}

func serveUDPEcho(pc net.PacketConn) {
	buf := make([]byte, 2048)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		_, _ = pc.WriteTo(buf[:n], addr)
	}
}

func generateFixtureCertificate(t *testing.T, host string) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate fixture key: %v", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate fixture serial: %v", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatalf("create fixture certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal fixture key: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("load fixture key pair: %v", err)
	}
	return cert
}

func fixtureTCPEchoAddr(ip string) string {
	return net.JoinHostPort(ip, fmt.Sprintf("%d", fixtureTCPEchoPort))
}

func fixtureUDPEchoAddr(ip string) string {
	return net.JoinHostPort(ip, fmt.Sprintf("%d", fixtureUDPEchoPort))
}

func tcpExchangeResult(target string, timeout time.Duration) string {
	if target == "" {
		return "error"
	}
	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		return classifyProbeError(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := io.WriteString(conn, integrationProbePayload); err != nil {
		return classifyProbeError(err)
	}
	buf := make([]byte, len(integrationProbePayload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return classifyProbeError(err)
	}
	if string(buf) != integrationProbePayload {
		return "error"
	}
	return "success"
}

type persistentTCPEchoProbe struct {
	conn net.Conn
}

func startPersistentTCPEchoProbe(target string, timeout time.Duration) (*persistentTCPEchoProbe, error) {
	if target == "" {
		return nil, fmt.Errorf("missing target")
	}
	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		return nil, err
	}
	probe := &persistentTCPEchoProbe{conn: conn}
	if got := probe.Exchange(timeout); got != "success" {
		_ = conn.Close()
		return nil, fmt.Errorf("initial exchange = %s", got)
	}
	return probe, nil
}

func (p *persistentTCPEchoProbe) Exchange(timeout time.Duration) string {
	if p == nil || p.conn == nil {
		return "error"
	}
	_ = p.conn.SetDeadline(time.Now().Add(timeout))
	if _, err := io.WriteString(p.conn, integrationProbePayload); err != nil {
		return classifyProbeError(err)
	}
	buf := make([]byte, len(integrationProbePayload))
	if _, err := io.ReadFull(p.conn, buf); err != nil {
		return classifyProbeError(err)
	}
	if string(buf) != integrationProbePayload {
		return "error"
	}
	return "success"
}

func (p *persistentTCPEchoProbe) Close() error {
	if p == nil || p.conn == nil {
		return nil
	}
	err := p.conn.Close()
	p.conn = nil
	return err
}

func TestPersistentTCPEchoProbeKeepsConnectionAliveAcrossExchanges(t *testing.T) {
	ln := mustListenTCP(t, "127.0.0.1:0")
	go serveTCPEcho(ln)
	t.Cleanup(func() {
		_ = ln.Close()
	})

	probe, err := startPersistentTCPEchoProbe(ln.Addr().String(), 300*time.Millisecond)
	if err != nil {
		t.Fatalf("startPersistentTCPEchoProbe() error = %v", err)
	}
	t.Cleanup(func() {
		_ = probe.Close()
	})

	if got := probe.Exchange(300 * time.Millisecond); got != "success" {
		t.Fatalf("second Exchange() = %q, want success", got)
	}
}

func udpExchangeResult(target string, timeout time.Duration) string {
	if target == "" {
		return "error"
	}
	conn, err := net.DialTimeout("udp", target, timeout)
	if err != nil {
		return classifyProbeError(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := io.WriteString(conn, integrationProbePayload); err != nil {
		return classifyProbeError(err)
	}
	buf := make([]byte, len(integrationProbePayload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return classifyProbeError(err)
	}
	if string(buf) != integrationProbePayload {
		return "error"
	}
	return "success"
}

func httpsProbeResult(targetAddr, serverName string, timeout time.Duration) string {
	if targetAddr == "" || serverName == "" {
		return "error"
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, targetAddr)
		},
		TLSClientConfig: &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: true,
		},
	}
	defer transport.CloseIdleConnections()

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, "https://"+serverName+"/healthz", nil)
	if err != nil {
		return "error"
	}
	resp, err := transport.RoundTrip(req)
	if err != nil {
		return classifyProbeError(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return "error"
	}
	return "success"
}

func icmpProbeResult(target string, timeout time.Duration) string {
	if target == "" {
		return "error"
	}
	waitSeconds := max(1, int(timeout/time.Second))
	ctx, cancel := context.WithTimeout(context.Background(), timeout+time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ping", "-n", "-c", "1", "-W", fmt.Sprintf("%d", waitSeconds), target)
	if err := cmd.Run(); err != nil {
		return classifyProbeError(err)
	}
	return "success"
}

func classifyProbeError(err error) string {
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return "timeout"
	}
	if err != nil && strings.Contains(err.Error(), "deadline exceeded") {
		return "timeout"
	}
	return "error"
}

func waitForProbeResults(t *testing.T, timeout time.Duration, probe func() string, accepted ...string) string {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		got := probe()
		for _, want := range accepted {
			if got == want {
				return got
			}
		}
		time.Sleep(100 * time.Millisecond)
	}

	t.Fatalf("timed out waiting for probe result in %v; want one of %v", timeout, accepted)
	return ""
}

func findLogLinesContaining(logs string, needles ...string) []string {
	lines := strings.Split(logs, "\n")
	var matches []string
	for _, line := range lines {
		if logLineContainsAll(line, needles...) {
			matches = append(matches, line)
		}
	}
	return matches
}
