package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
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
	interval    time.Duration
	timeout     time.Duration
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
	interval := flag.Duration("interval", 1*time.Second, "probe interval")
	timeout := flag.Duration("timeout", 2*time.Second, "probe timeout")
	flag.Parse()

	return probeConfig{
		fixture:     *fixture,
		proxyDNS:    normalizeAddr(*proxyDNS, "53"),
		upstreamDNS: normalizeAddr(*upstreamDNS, "53"),
		allowedHost: *allowedHost,
		blockedHost: *blockedHost,
		interval:    *interval,
		timeout:     *timeout,
	}
}

func runProbeCycle(cfg probeConfig, w io.Writer) {
	emitResult(w, probeResult{
		Kind:   "tcp",
		Phase:  "direct",
		Target: cfg.fixture,
		Result: tcpProbe(cfg.fixture, cfg.timeout),
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
		Target: cfg.fixture,
		Result: tcpProbe(cfg.fixture, cfg.timeout),
	})
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
		if len(resp.Answer) == 0 {
			return "nxdomain"
		}
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

func normalizeAddr(addr, defaultPort string) string {
	if addr == "" {
		return addr
	}
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	if strings.Contains(addr, ":") {
		return addr
	}
	return net.JoinHostPort(addr, defaultPort)
}
