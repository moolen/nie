package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

type probeResult struct {
	Kind   string
	Phase  string
	Target string
	Result string
}

type probeConfig struct {
	fixture     string
	proxyDNS    string
	upstreamDNS string
	allowedHost string
	blockedHost string
	httpsPorts  []int
	interval    time.Duration
	timeout     time.Duration
}

const probePayload = "nie-probe"

const (
	fixtureTCPEchoPort = 18081
	fixtureUDPEchoPort = 18082
)

var runICMPCommand = func(ctx context.Context, target string, timeout time.Duration) error {
	waitSeconds := max(1, int(timeout/time.Second))
	cmd := exec.CommandContext(ctx, "ping", "-n", "-c", "1", "-W", fmt.Sprintf("%d", waitSeconds), target)
	return cmd.Run()
}

func formatProbeResult(r probeResult) string {
	return fmt.Sprintf("kind=%s phase=%s target=%s result=%s", r.Kind, r.Phase, r.Target, r.Result)
}

func emitResult(w io.Writer, r probeResult) {
	fmt.Fprintln(w, formatProbeResult(r))
}

func main() {
	cfg := parseConfig()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	runProbeCycle(cfg, os.Stdout)

	ticker := time.NewTicker(cfg.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runProbeCycle(cfg, os.Stdout)
		}
	}
}

func parseConfig() probeConfig {
	fixture := flag.String("fixture", "", "fixture host:port")
	proxyDNS := flag.String("proxy-dns", "", "proxy DNS host:port")
	upstreamDNS := flag.String("upstream-dns", "", "upstream DNS host:port")
	allowedHost := flag.String("allowed-host", "", "allowed hostname")
	blockedHost := flag.String("blocked-host", "", "blocked hostname")
	httpsPorts := flag.String("https-ports", "443,8443", "comma-separated HTTPS fixture ports")
	interval := flag.Duration("interval", 1*time.Second, "probe interval")
	timeout := flag.Duration("timeout", 2*time.Second, "probe timeout")
	flag.Parse()

	parsedHTTPSPorts, err := parsePortList(*httpsPorts, []int{443, 8443})
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse https ports: %v\n", err)
		os.Exit(2)
	}

	return probeConfig{
		fixture:     *fixture,
		proxyDNS:    normalizeAddr(*proxyDNS, "53"),
		upstreamDNS: normalizeAddr(*upstreamDNS, "53"),
		allowedHost: *allowedHost,
		blockedHost: *blockedHost,
		httpsPorts:  parsedHTTPSPorts,
		interval:    *interval,
		timeout:     *timeout,
	}
}

func runProbeCycle(cfg probeConfig, w io.Writer) {
	fixtureIP := fixtureIP(cfg.fixture)
	emitResult(w, probeResult{
		Kind:   "tcp",
		Phase:  "direct",
		Target: fixtureTCPEchoAddr(fixtureIP),
		Result: tcpExchangeProbe(fixtureTCPEchoAddr(fixtureIP), cfg.timeout),
	})
	emitResult(w, probeResult{
		Kind:   "udp",
		Phase:  "direct",
		Target: fixtureUDPEchoAddr(fixtureIP),
		Result: udpExchangeProbe(fixtureUDPEchoAddr(fixtureIP), cfg.timeout),
	})
	emitResult(w, probeResult{
		Kind:   "icmp",
		Phase:  "direct",
		Target: fixtureIP,
		Result: icmpProbe(fixtureIP, cfg.timeout),
	})
	emitResult(w, probeResult{
		Kind:   "dns",
		Phase:  "blocked-upstream",
		Target: cfg.blockedHost,
		Result: dnsProbe(cfg.upstreamDNS, cfg.blockedHost, cfg.timeout),
	})
	emitResult(w, probeResult{
		Kind:   "dns",
		Phase:  "blocked-proxy",
		Target: cfg.blockedHost,
		Result: dnsProbe(cfg.proxyDNS, cfg.blockedHost, cfg.timeout),
	})
	emitResult(w, probeResult{
		Kind:   "dns",
		Phase:  "allowed-proxy",
		Target: cfg.allowedHost,
		Result: dnsProbe(cfg.proxyDNS, cfg.allowedHost, cfg.timeout),
	})
	emitResult(w, probeResult{
		Kind:   "tcp",
		Phase:  "learned",
		Target: fixtureTCPEchoAddr(fixtureIP),
		Result: tcpExchangeProbe(fixtureTCPEchoAddr(fixtureIP), cfg.timeout),
	})
	emitResult(w, probeResult{
		Kind:   "udp",
		Phase:  "learned",
		Target: fixtureUDPEchoAddr(fixtureIP),
		Result: udpExchangeProbe(fixtureUDPEchoAddr(fixtureIP), cfg.timeout),
	})
	emitResult(w, probeResult{
		Kind:   "icmp",
		Phase:  "learned",
		Target: fixtureIP,
		Result: icmpProbe(fixtureIP, cfg.timeout),
	})
	for _, port := range cfg.httpsPorts {
		portStr := strconv.Itoa(port)
		emitResult(w, probeResult{
			Kind:   "https",
			Phase:  blockedHTTPSPhase(port),
			Target: net.JoinHostPort(cfg.blockedHost, portStr),
			Result: httpsProbe(net.JoinHostPort(fixtureIP, portStr), cfg.blockedHost, cfg.timeout),
		})
	}
}

func tcpProbe(target string, timeout time.Duration) string {
	if target == "" {
		return "error"
	}
	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		return classifyNetError(err)
	}
	_ = conn.Close()
	return "success"
}

func tcpExchangeProbe(target string, timeout time.Duration) string {
	if target == "" {
		return "error"
	}
	conn, err := net.DialTimeout("tcp", target, timeout)
	if err != nil {
		return classifyNetError(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := io.WriteString(conn, probePayload); err != nil {
		return classifyNetError(err)
	}
	buf := make([]byte, len(probePayload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return classifyNetError(err)
	}
	if string(buf) != probePayload {
		return "error"
	}
	return "success"
}

func udpExchangeProbe(target string, timeout time.Duration) string {
	if target == "" {
		return "error"
	}
	conn, err := net.DialTimeout("udp", target, timeout)
	if err != nil {
		return classifyNetError(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := io.WriteString(conn, probePayload); err != nil {
		return classifyNetError(err)
	}
	buf := make([]byte, len(probePayload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return classifyNetError(err)
	}
	if string(buf) != probePayload {
		return "error"
	}
	return "success"
}

func httpsProbe(targetAddr, serverName string, timeout time.Duration) string {
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
		return classifyNetError(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return "error"
	}
	return "success"
}

func icmpProbe(target string, timeout time.Duration) string {
	if target == "" {
		return "error"
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout+time.Second)
	defer cancel()
	if err := runICMPCommand(ctx, target, timeout); err != nil {
		return classifyNetError(err)
	}
	return "success"
}

func dnsProbe(server, host string, timeout time.Duration) string {
	if server == "" || host == "" {
		return "error"
	}
	client := &dns.Client{Timeout: timeout}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(host), dns.TypeA)
	resp, _, err := client.Exchange(msg, server)
	if err != nil {
		return classifyNetError(err)
	}
	switch resp.Rcode {
	case dns.RcodeSuccess:
		return "success"
	case dns.RcodeNameError:
		return "nxdomain"
	case dns.RcodeRefused:
		return "refused"
	default:
		return "error"
	}
}

func classifyNetError(err error) string {
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return "timeout"
	}
	return "error"
}

func fixtureIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	return host
}

func fixtureTCPEchoAddr(ip string) string {
	if ip == "" {
		return ""
	}
	return net.JoinHostPort(ip, fmt.Sprintf("%d", fixtureTCPEchoPort))
}

func fixtureUDPEchoAddr(ip string) string {
	if ip == "" {
		return ""
	}
	return net.JoinHostPort(ip, fmt.Sprintf("%d", fixtureUDPEchoPort))
}

func blockedHTTPSPhase(port int) string {
	return fmt.Sprintf("blocked-%d", port)
}

func parsePortList(raw string, defaults []int) ([]int, error) {
	if strings.TrimSpace(raw) == "" {
		return append([]int(nil), defaults...), nil
	}

	parts := strings.Split(raw, ",")
	ports := make([]int, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, errors.New("empty port")
		}
		port, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("parse port %q: %w", part, err)
		}
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("port %d out of range", port)
		}
		ports = append(ports, port)
	}
	return ports, nil
}

func normalizeAddr(addr, defaultPort string) string {
	if addr == "" {
		return addr
	}
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	if strings.Contains(addr, ":") {
		base := addr
		if idx := strings.Index(base, "%"); idx != -1 {
			base = base[:idx]
		}
		if ip := net.ParseIP(base); ip != nil {
			return net.JoinHostPort(addr, defaultPort)
		}
		return addr
	}
	return net.JoinHostPort(addr, defaultPort)
}
