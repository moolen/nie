//go:build integration

package test

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/miekg/dns"

	"github.com/moolen/nie/internal/netx"
)

const (
	spectreRepoURL   = "https://github.com/moolen/spectre"
	spectrePinnedRev = "e49f8e0899616842cff5441bc4d9ee10c0667f20"
)

func TestSmoke_AuditModeAllowsUnknownTrafficButEmitsWouldDeny(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}

	root := repoRoot(t)
	tmpDir := t.TempDir()
	fixture := startIntegrationFixture(t, "127.0.0.2")
	cleanupStaleNieRedirectState(t)

	binPath := resolveNieBinary(t, root, tmpDir)

	upstreamAddr := startFakeUpstream(t, fixture.IP)
	listenAddr := pickFreeListenAddr(t)
	httpsListenAddr := pickFreeTCPAddr(t)
	configPath := filepath.Join(tmpDir, "config.yaml")
	writeConfig(t, configPath, writeConfigOptions{
		mode:            "audit",
		iface:           "lo",
		listenAddr:      listenAddr,
		httpsListenAddr: httpsListenAddr,
		upstreamAddr:    upstreamAddr,
		allowHosts:      []string{"allowed.example.com"},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, binPath, "-config", configPath)
	cmd.Dir = root

	var logs lockedBuffer
	cmd.Stdout = &logs
	cmd.Stderr = &logs

	waitCh := make(chan error, 1)

	if err := cmd.Start(); err != nil {
		t.Fatalf("start nie: %v", err)
	}
	stopped := false
	t.Cleanup(func() {
		if !stopped {
			_ = terminateNieProcess(cmd, waitCh, &logs)
		}
	})
	go func() {
		waitCh <- cmd.Wait()
	}()

	waitForPinnedState(t, "/sys/fs/bpf/nie", true, waitCh, &logs)
	waitForNieRedirectState(t, true, waitCh, &logs)

	if got := waitForProbeResults(t, 5*time.Second, func() string {
		return tcpExchangeResult(fixtureTCPEchoAddr(fixture.IP), 300*time.Millisecond)
	}, "success"); got != "success" {
		t.Fatalf("tcp direct result = %q, want success", got)
	}
	if got := waitForProbeResults(t, 5*time.Second, func() string {
		return udpExchangeResult(fixtureUDPEchoAddr(fixture.IP), 300*time.Millisecond)
	}, "success"); got != "success" {
		t.Fatalf("udp direct result = %q, want success", got)
	}
	if got := waitForProbeResults(t, 5*time.Second, func() string {
		return icmpProbeResult(fixture.IP, time.Second)
	}, "success"); got != "success" {
		t.Fatalf("icmp direct result = %q, want success", got)
	}
	if got := waitForProbeResults(t, 5*time.Second, func() string {
		return httpsProbeResult(net.JoinHostPort(fixture.IP, "443"), "blocked.example.com", 750*time.Millisecond)
	}, "error", "timeout"); got == "" {
		t.Fatal("https 443 probe did not reach blocked outcome")
	}
	if got := waitForProbeResults(t, 5*time.Second, func() string {
		return httpsProbeResult(net.JoinHostPort(fixture.IP, "8443"), "blocked.example.com", 750*time.Millisecond)
	}, "error", "timeout"); got == "" {
		t.Fatal("https 8443 probe did not reach blocked outcome")
	}

	resp := waitForAnswer(t, listenAddr, "blocked.example.com.", waitCh, &logs)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %d, want %d; logs=%s", resp.Rcode, dns.RcodeSuccess, logs.String())
	}
	if !hasIPv4Answer(resp, fixture.IP) {
		t.Fatalf("response answers = %#v, want A %s", resp.Answer, fixture.IP)
	}

	waitForLog(t, "would_deny_dns", waitCh, &logs)
	waitForLog(t, "host=blocked.example.com", waitCh, &logs)
	waitForLog(t, "would_deny_egress", waitCh, &logs)
	waitForLog(t, "proto=tcp", waitCh, &logs)
	waitForLog(t, fmt.Sprintf("port=%d", fixtureTCPEchoPort), waitCh, &logs)
	waitForLog(t, "proto=udp", waitCh, &logs)
	waitForLog(t, fmt.Sprintf("port=%d", fixtureUDPEchoPort), waitCh, &logs)
	waitForLog(t, "proto=icmp", waitCh, &logs)
	waitForLog(t, "port=0", waitCh, &logs)
	waitForLog(t, "would_deny_https", waitCh, &logs)
	waitForLog(t, "host=blocked.example.com", waitCh, &logs)
	waitForLog(t, "port=443", waitCh, &logs)
	waitForLog(t, "port=8443", waitCh, &logs)

	for _, line := range findLogLinesContaining(logs.String(), "would_deny_dns") {
		t.Logf("nie: %s", line)
	}
	for _, line := range findLogLinesContaining(logs.String(), "would_deny_egress") {
		t.Logf("nie: %s", line)
	}
	for _, line := range findLogLinesContaining(logs.String(), "would_deny_https") {
		t.Logf("nie: %s", line)
	}

	if err := terminateNieProcess(cmd, waitCh, &logs); err != nil {
		t.Fatalf("wait for nie exit: %v; logs=%s", err, logs.String())
	}
	stopped = true

	waitForPinnedStateAfterExit(t, "/sys/fs/bpf/nie", false)
	waitForNieRedirectStateAfterExit(t, false)
}

func TestSmoke_EnforceBlocksUnknownTrafficUntilDNSLearning(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	if os.Getenv("NIE_ENABLE_LOOPBACK_ENFORCE_SMOKE") != "1" {
		t.Skip("loopback enforce smoke is opt-in; enforce behavior is covered in VM e2e where DNS control-plane traffic does not traverse the protected loopback path")
	}

	root := repoRoot(t)
	tmpDir := t.TempDir()
	fixture := startIntegrationFixture(t, "127.0.0.2")
	cleanupStaleNieRedirectState(t)

	binPath := resolveNieBinary(t, root, tmpDir)
	upstreamAddr := startFakeUpstream(t, fixture.IP)
	listenAddr := pickFreeListenAddr(t)
	httpsListenAddr := pickFreeTCPAddr(t)
	configPath := filepath.Join(tmpDir, "config.yaml")
	writeConfig(t, configPath, writeConfigOptions{
		mode:            "enforce",
		iface:           "lo",
		listenAddr:      listenAddr,
		httpsListenAddr: httpsListenAddr,
		upstreamAddr:    upstreamAddr,
		allowHosts:      []string{"allowed.example.com"},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, binPath, "-config", configPath)
	cmd.Dir = root

	var logs lockedBuffer
	cmd.Stdout = &logs
	cmd.Stderr = &logs

	waitCh := make(chan error, 1)

	if err := cmd.Start(); err != nil {
		t.Fatalf("start nie: %v", err)
	}
	stopped := false
	t.Cleanup(func() {
		if !stopped {
			_ = terminateNieProcess(cmd, waitCh, &logs)
		}
	})
	go func() {
		waitCh <- cmd.Wait()
	}()

	waitForPinnedState(t, "/sys/fs/bpf/nie", true, waitCh, &logs)
	waitForNieRedirectState(t, true, waitCh, &logs)

	if got := waitForProbeResults(t, 5*time.Second, func() string {
		return tcpExchangeResult(fixtureTCPEchoAddr(fixture.IP), 300*time.Millisecond)
	}, "error", "timeout"); got == "" {
		t.Fatal("tcp direct probe did not block")
	}
	if got := waitForProbeResults(t, 5*time.Second, func() string {
		return udpExchangeResult(fixtureUDPEchoAddr(fixture.IP), 300*time.Millisecond)
	}, "error", "timeout"); got == "" {
		t.Fatal("udp direct probe did not block")
	}
	if got := waitForProbeResults(t, 5*time.Second, func() string {
		return icmpProbeResult(fixture.IP, time.Second)
	}, "error", "timeout"); got == "" {
		t.Fatal("icmp direct probe did not block")
	}
	if got := waitForProbeResults(t, 5*time.Second, func() string {
		return httpsProbeResult(net.JoinHostPort(fixture.IP, "443"), "blocked.example.com", 750*time.Millisecond)
	}, "error", "timeout"); got == "" {
		t.Fatal("https 443 probe did not block")
	}
	if got := waitForProbeResults(t, 5*time.Second, func() string {
		return httpsProbeResult(net.JoinHostPort(fixture.IP, "8443"), "blocked.example.com", 750*time.Millisecond)
	}, "error", "timeout"); got == "" {
		t.Fatal("https 8443 probe did not block")
	}

	resp := waitForMarkedAnswer(t, 4242, listenAddr, "allowed.example.com.", waitCh, &logs)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %d, want %d; logs=%s", resp.Rcode, dns.RcodeSuccess, logs.String())
	}
	if !hasIPv4Answer(resp, fixture.IP) {
		t.Fatalf("response answers = %#v, want A %s", resp.Answer, fixture.IP)
	}

	if got := waitForProbeResults(t, 5*time.Second, func() string {
		return tcpExchangeResult(fixtureTCPEchoAddr(fixture.IP), 300*time.Millisecond)
	}, "success"); got != "success" {
		t.Fatalf("tcp learned result = %q, want success", got)
	}
	if got := waitForProbeResults(t, 5*time.Second, func() string {
		return udpExchangeResult(fixtureUDPEchoAddr(fixture.IP), 300*time.Millisecond)
	}, "success"); got != "success" {
		t.Fatalf("udp learned result = %q, want success", got)
	}
	if got := waitForProbeResults(t, 5*time.Second, func() string {
		return icmpProbeResult(fixture.IP, time.Second)
	}, "success"); got != "success" {
		t.Fatalf("icmp learned result = %q, want success", got)
	}

	if err := terminateNieProcess(cmd, waitCh, &logs); err != nil {
		t.Fatalf("wait for nie exit: %v; logs=%s", err, logs.String())
	}
	stopped = true

	waitForPinnedStateAfterExit(t, "/sys/fs/bpf/nie", false)
	waitForNieRedirectStateAfterExit(t, false)
}

func TestSmoke_EnforceKeepsActiveTCPFlowAcrossDNSRotationAndEventuallyPrunesStaleIP(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	if os.Getenv("NIE_ENABLE_LOOPBACK_ENFORCE_SMOKE") != "1" {
		t.Skip("loopback enforce smoke is opt-in; enforce behavior is covered in VM e2e where DNS control-plane traffic does not traverse the protected loopback path")
	}

	root := repoRoot(t)
	tmpDir := t.TempDir()
	fixtureA := startIntegrationFixture(t, "127.0.0.2")
	fixtureB := startIntegrationFixture(t, "127.0.0.3")
	cleanupStaleNieRedirectState(t)

	binPath := resolveNieBinary(t, root, tmpDir)
	upstream := startRotatingFakeUpstreamWithTTL(t, fixtureA.IP, 1)
	listenAddr := pickFreeListenAddr(t)
	httpsListenAddr := pickFreeTCPAddr(t)
	configPath := filepath.Join(tmpDir, "config.yaml")
	writeConfig(t, configPath, writeConfigOptions{
		mode:               "enforce",
		iface:              "lo",
		listenAddr:         listenAddr,
		httpsListenAddr:    httpsListenAddr,
		upstreamAddr:       upstream.Addr(),
		allowHosts:         []string{"allowed.example.com"},
		trustMaxStaleHold:  "0s",
		trustSweepInterval: "100ms",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, binPath, "-config", configPath)
	cmd.Dir = root

	var logs lockedBuffer
	cmd.Stdout = &logs
	cmd.Stderr = &logs

	waitCh := make(chan error, 1)

	if err := cmd.Start(); err != nil {
		t.Fatalf("start nie: %v", err)
	}
	stopped := false
	t.Cleanup(func() {
		if !stopped {
			_ = terminateNieProcess(cmd, waitCh, &logs)
		}
	})
	go func() {
		waitCh <- cmd.Wait()
	}()

	waitForPinnedState(t, "/sys/fs/bpf/nie", true, waitCh, &logs)
	waitForNieRedirectState(t, true, waitCh, &logs)

	respA := waitForMarkedAnswer(t, 4242, listenAddr, "allowed.example.com.", waitCh, &logs)
	if respA.Rcode != dns.RcodeSuccess {
		t.Fatalf("first rcode = %d, want %d; logs=%s", respA.Rcode, dns.RcodeSuccess, logs.String())
	}
	if !hasIPv4Answer(respA, fixtureA.IP) {
		t.Fatalf("first response answers = %#v, want A %s", respA.Answer, fixtureA.IP)
	}

	longLivedProbe, err := startPersistentTCPEchoProbe(fixtureTCPEchoAddr(fixtureA.IP), 300*time.Millisecond)
	if err != nil {
		t.Fatalf("start persistent tcp probe: %v", err)
	}
	t.Cleanup(func() {
		_ = longLivedProbe.Close()
	})

	upstream.SetAnswerIP(fixtureB.IP)

	respB := waitForMarkedAnswer(t, 4242, listenAddr, "allowed.example.com.", waitCh, &logs)
	if respB.Rcode != dns.RcodeSuccess {
		t.Fatalf("second rcode = %d, want %d; logs=%s", respB.Rcode, dns.RcodeSuccess, logs.String())
	}
	if !hasIPv4Answer(respB, fixtureB.IP) {
		t.Fatalf("second response answers = %#v, want A %s", respB.Answer, fixtureB.IP)
	}

	time.Sleep(1500 * time.Millisecond)

	if got := waitForProbeResults(t, 5*time.Second, func() string {
		return tcpExchangeResult(fixtureTCPEchoAddr(fixtureB.IP), 300*time.Millisecond)
	}, "success"); got != "success" {
		t.Fatalf("fresh tcp flow to rotated IP result = %q, want success", got)
	}

	if got := waitForProbeResults(t, 5*time.Second, func() string {
		return longLivedProbe.Exchange(300 * time.Millisecond)
	}, "success"); got != "success" {
		t.Fatalf("long-lived tcp flow result after rotation = %q, want success", got)
	}

	if err := longLivedProbe.Close(); err != nil {
		t.Fatalf("close persistent tcp probe: %v", err)
	}

	waitForBlockedProbe(t, 2*time.Minute, func() string {
		return tcpExchangeResult(fixtureTCPEchoAddr(fixtureA.IP), 300*time.Millisecond)
	})

	if err := terminateNieProcess(cmd, waitCh, &logs); err != nil {
		t.Fatalf("wait for nie exit: %v; logs=%s", err, logs.String())
	}
	stopped = true

	waitForPinnedStateAfterExit(t, "/sys/fs/bpf/nie", false)
	waitForNieRedirectStateAfterExit(t, false)
}

func TestExtractAuditedDomains(t *testing.T) {
	logs := strings.Join([]string{
		`time=2026-04-05T00:00:00Z level=INFO msg=would_deny_dns host=registry.npmjs.org.`,
		`time=2026-04-05T00:00:01Z level=INFO msg=would_deny_dns host=proxy.golang.org.`,
		`time=2026-04-05T00:00:02Z level=INFO msg=would_deny_https host=AUTH.DOCKER.IO`,
		`time=2026-04-05T00:00:03Z level=INFO msg=would_deny_egress proto=tcp dst=203.0.113.10 port=443`,
		`time=2026-04-05T00:00:04Z level=INFO msg=would_deny_https host=registry-1.docker.io`,
		`time=2026-04-05T00:00:05Z level=INFO msg=would_deny_https host=REGISTRY-1.DOCKER.IO..`,
		`time=2026-04-05T00:00:05Z level=INFO msg=would_deny_dns host=registry.npmjs.org.`,
	}, "\n")

	got := sortedDomainSet(extractAuditedDomains(logs))
	want := []string{
		"auth.docker.io",
		"proxy.golang.org",
		"registry-1.docker.io",
		"registry.npmjs.org",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sortedDomainSet(extractAuditedDomains()) = %v, want %v", got, want)
	}
}

func TestParseDefaultRouteInterface(t *testing.T) {
	got, err := parseDefaultRouteInterface("default via 192.0.2.1 dev eth0 proto dhcp src 192.0.2.10 metric 100")
	if err != nil {
		t.Fatalf("parseDefaultRouteInterface() error = %v, want nil", err)
	}
	if got != "eth0" {
		t.Fatalf("parseDefaultRouteInterface() = %q, want %q", got, "eth0")
	}
}

func TestNormalizeAuditedDomain(t *testing.T) {
	got := normalizeAuditedDomain("AUTH.DOCKER.IO.")
	if got != "auth.docker.io" {
		t.Fatalf("normalizeAuditedDomain() = %q, want %q", got, "auth.docker.io")
	}
}

func extractAuditedDomains(logs string) map[string]struct{} {
	domains := make(map[string]struct{})
	scanner := bufio.NewScanner(strings.NewReader(logs))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "would_deny_dns") && !strings.Contains(line, "would_deny_https") {
			continue
		}
		host, ok := logFieldValue(line, "host=")
		if !ok {
			continue
		}
		host = normalizeAuditedDomain(host)
		if host == "" {
			continue
		}
		domains[host] = struct{}{}
	}
	return domains
}

func sortedDomainSet(set map[string]struct{}) []string {
	domains := make([]string, 0, len(set))
	for domain := range set {
		domains = append(domains, domain)
	}
	sort.Strings(domains)
	return domains
}

func logFieldValue(line, key string) (string, bool) {
	idx := strings.Index(line, key)
	if idx < 0 {
		return "", false
	}
	value := line[idx+len(key):]
	if end := strings.IndexByte(value, ' '); end >= 0 {
		value = value[:end]
	}
	return value, value != ""
}

func normalizeAuditedDomain(host string) string {
	return strings.TrimRight(strings.ToLower(strings.TrimSpace(host)), ".")
}

func defaultRouteInterface(t *testing.T) string {
	t.Helper()

	output, err := exec.Command("ip", "route", "show", "default").CombinedOutput()
	if err != nil {
		t.Fatalf("ip route show default: %v\n%s", err, output)
	}
	iface, err := parseDefaultRouteInterface(string(output))
	if err != nil {
		t.Fatalf("parse default route interface: %v\n%s", err, output)
	}
	return iface
}

func parseDefaultRouteInterface(output string) (string, error) {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		for i := 0; i < len(fields)-1; i++ {
			if fields[i] == "dev" && fields[i+1] != "" {
				return fields[i+1], nil
			}
		}
	}
	return "", errors.New("default route interface not found")
}

func checkoutPinnedSpectre(t *testing.T, dir string) string {
	t.Helper()

	repoDir := filepath.Join(dir, "spectre")

	clone := exec.Command("git", "clone", "--depth", "1", spectreRepoURL, repoDir)
	if output, err := clone.CombinedOutput(); err != nil {
		t.Fatalf("git clone spectre: %v\n%s", err, output)
	}

	fetch := exec.Command("git", "-C", repoDir, "fetch", "--depth", "1", "origin", spectrePinnedRev)
	if output, err := fetch.CombinedOutput(); err != nil {
		t.Fatalf("git fetch spectre pinned rev: %v\n%s", err, output)
	}

	checkout := exec.Command("git", "-C", repoDir, "checkout", "--detach", spectrePinnedRev)
	if output, err := checkout.CombinedOutput(); err != nil {
		t.Fatalf("git checkout spectre pinned rev: %v\n%s", err, output)
	}

	return repoDir
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func repoRoot(t *testing.T) string {
	t.Helper()

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller() failed")
	}
	return filepath.Dir(filepath.Dir(file))
}

func buildNieBinary(t *testing.T, root, out string) {
	t.Helper()

	cmd := exec.Command("go", "build", "-buildvcs=false", "-o", out, "./cmd/nie")
	cmd.Dir = root
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build ./cmd/nie: %v\n%s", err, output)
	}
}

func resolveNieBinary(t *testing.T, root, tmpDir string) string {
	t.Helper()

	if path := strings.TrimSpace(os.Getenv("NIE_TEST_BIN")); path != "" {
		return path
	}

	binPath := filepath.Join(tmpDir, "nie")
	buildNieBinary(t, root, binPath)
	return binPath
}

func startFakeUpstream(t *testing.T, answerIP string) string {
	t.Helper()

	return startRotatingFakeUpstream(t, answerIP).Addr()
}

type rotatingFakeUpstream struct {
	mu       sync.RWMutex
	answerIP string
	server   *dns.Server
	pc       net.PacketConn
}

func startRotatingFakeUpstream(t *testing.T, answerIP string) *rotatingFakeUpstream {
	t.Helper()

	return startRotatingFakeUpstreamWithTTL(t, answerIP, 60)
}

func startRotatingFakeUpstreamWithTTL(t *testing.T, answerIP string, ttl uint32) *rotatingFakeUpstream {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen fake upstream: %v", err)
	}

	upstream := &rotatingFakeUpstream{
		answerIP: answerIP,
		pc:       pc,
	}

	handler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		if len(req.Question) == 1 && req.Question[0].Qtype == dns.TypeA {
			answerIP := upstream.answer()
			if ip := net.ParseIP(answerIP).To4(); ip != nil {
				resp.Answer = []dns.RR{&dns.A{
					Hdr: dns.RR_Header{
						Name:   req.Question[0].Name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    ttl,
					},
					A: ip,
				}}
			}
		}
		_ = w.WriteMsg(resp)
	})

	upstream.server = &dns.Server{
		PacketConn: pc,
		Handler:    handler,
	}

	go func() {
		_ = upstream.server.ActivateAndServe()
	}()

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = upstream.server.ShutdownContext(ctx)
		_ = pc.Close()
	})

	return upstream
}

func (u *rotatingFakeUpstream) Addr() string {
	return u.pc.LocalAddr().String()
}

func (u *rotatingFakeUpstream) SetAnswerIP(answerIP string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.answerIP = answerIP
}

func (u *rotatingFakeUpstream) answer() string {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.answerIP
}

func pickFreeListenAddr(t *testing.T) string {
	t.Helper()

	for range 32 {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("reserve tcp port: %v", err)
		}
		port := ln.Addr().(*net.TCPAddr).Port

		pc, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			_ = ln.Close()
			continue
		}

		if err := pc.Close(); err != nil {
			t.Fatalf("close reserved udp port: %v", err)
		}
		if err := ln.Close(); err != nil {
			t.Fatalf("close reserved tcp port: %v", err)
		}

		return fmt.Sprintf("127.0.0.1:%d", port)
	}

	t.Fatal("failed to reserve matching tcp/udp listen port")
	return ""
}

func pickFreeTCPAddr(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve tcp port: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("close reserved tcp port: %v", err)
	}
	return addr
}

type writeConfigOptions struct {
	mode               string
	iface              string
	listenAddr         string
	httpsListenAddr    string
	upstreamAddr       string
	allowHosts         []string
	trustMaxStaleHold  string
	trustSweepInterval string
}

func writeConfig(t *testing.T, path string, opts writeConfigOptions) {
	t.Helper()

	allowSection := ""
	for _, host := range opts.allowHosts {
		allowSection += fmt.Sprintf("    - %s\n", host)
	}

	trustSection := ""
	if opts.trustMaxStaleHold != "" || opts.trustSweepInterval != "" {
		trustSection = "trust:\n"
		if opts.trustMaxStaleHold != "" {
			trustSection += fmt.Sprintf("  max_stale_hold: %s\n", opts.trustMaxStaleHold)
		}
		if opts.trustSweepInterval != "" {
			trustSection += fmt.Sprintf("  sweep_interval: %s\n", opts.trustSweepInterval)
		}
	}

	raw := fmt.Sprintf(`mode: %s
interface: %s
dns:
  listen: %s
  upstreams:
    - %s
  mark: 4242
policy:
  default: deny
  allow:
%s
%shttps:
  listen: %s
  ports:
    - 443
    - 8443
`, opts.mode, opts.iface, opts.listenAddr, opts.upstreamAddr, allowSection, trustSection, opts.httpsListenAddr)

	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

func waitForAnswer(t *testing.T, addr, name string, waitCh <-chan error, logs *lockedBuffer) *dns.Msg {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	client := &dns.Client{Timeout: 250 * time.Millisecond}

	for time.Now().Before(deadline) {
		select {
		case err := <-waitCh:
			t.Fatalf("nie exited before answering DNS query: %v; logs=%s", err, logs.String())
		default:
		}

		req := new(dns.Msg)
		req.SetQuestion(name, dns.TypeA)

		resp, _, err := client.Exchange(req, addr)
		if err == nil && resp != nil {
			return resp
		}

		time.Sleep(100 * time.Millisecond)
	}

	t.Fatalf("timed out waiting for DNS answer from %s; logs=%s", addr, logs.String())
	return nil
}

func waitForMarkedAnswer(t *testing.T, mark uint32, addr, name string, waitCh <-chan error, logs *lockedBuffer) *dns.Msg {
	t.Helper()

	dialer, err := netx.NewMarkedDialer(mark)
	if err != nil {
		t.Fatalf("create marked dialer: %v", err)
	}
	dialer.Timeout = 250 * time.Millisecond

	deadline := time.Now().Add(10 * time.Second)
	client := &dns.Client{
		Net:     "tcp",
		Timeout: 250 * time.Millisecond,
		Dialer:  dialer,
	}

	for time.Now().Before(deadline) {
		select {
		case err := <-waitCh:
			t.Fatalf("nie exited before answering marked DNS query: %v; logs=%s", err, logs.String())
		default:
		}

		req := new(dns.Msg)
		req.SetQuestion(name, dns.TypeA)

		resp, _, err := client.Exchange(req, addr)
		if err == nil && resp != nil {
			return resp
		}

		time.Sleep(100 * time.Millisecond)
	}

	t.Fatalf("timed out waiting for marked DNS answer from %s; logs=%s", addr, logs.String())
	return nil
}

func hasIPv4Answer(resp *dns.Msg, want string) bool {
	for _, rr := range resp.Answer {
		a, ok := rr.(*dns.A)
		if ok && a.A.String() == want {
			return true
		}
	}
	return false
}

func waitForBlockedProbe(t *testing.T, timeout time.Duration, probe func() string) {
	t.Helper()

	if got := waitForProbeResults(t, timeout, probe, "error", "timeout"); got == "" {
		t.Fatal("probe did not become blocked")
	}
}

func waitForLog(t *testing.T, needle string, waitCh <-chan error, logs *lockedBuffer) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(logs.String(), needle) {
			return
		}
		select {
		case err := <-waitCh:
			t.Fatalf("nie exited before log %q appeared: %v; logs=%s", needle, err, logs.String())
		default:
		}
		time.Sleep(50 * time.Millisecond)
	}

	t.Fatalf("log output %q does not contain %q", logs.String(), needle)
}

func waitForPinnedState(t *testing.T, path string, wantExists bool, waitCh <-chan error, logs *lockedBuffer) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_, err := os.Stat(path)
		exists := err == nil
		if exists == wantExists {
			return
		}
		if err != nil && !os.IsNotExist(err) {
			t.Fatalf("stat %s: %v", path, err)
		}

		select {
		case runErr := <-waitCh:
			t.Fatalf("nie exited before pinned-state assertion: %v; logs=%s", runErr, logs.String())
		default:
		}
		time.Sleep(50 * time.Millisecond)
	}

	t.Fatalf("timed out waiting for pinned state at %s to be exists=%t", path, wantExists)
}

func waitForPinnedStateAfterExit(t *testing.T, path string, wantExists bool) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_, err := os.Stat(path)
		exists := err == nil
		if exists == wantExists {
			return
		}
		if err != nil && !os.IsNotExist(err) {
			t.Fatalf("stat %s: %v", path, err)
		}
		time.Sleep(50 * time.Millisecond)
	}

	t.Fatalf("timed out waiting after exit for pinned state at %s to be exists=%t", path, wantExists)
}

func waitForNieRedirectState(t *testing.T, wantInstalled bool, waitCh <-chan error, logs *lockedBuffer) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		installed, err := nieRedirectInstalled()
		if err != nil {
			t.Fatalf("query nftables state: %v", err)
		}
		if installed == wantInstalled {
			return
		}

		select {
		case runErr := <-waitCh:
			t.Fatalf("nie exited before redirect-state assertion: %v; logs=%s", runErr, logs.String())
		default:
		}
		time.Sleep(50 * time.Millisecond)
	}

	t.Fatalf("timed out waiting for nftables redirect state installed=%t", wantInstalled)
}

func waitForNieRedirectStateAfterExit(t *testing.T, wantInstalled bool) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		installed, err := nieRedirectInstalled()
		if err != nil {
			t.Fatalf("query nftables state: %v", err)
		}
		if installed == wantInstalled {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}

	t.Fatalf("timed out waiting after exit for nftables redirect state installed=%t", wantInstalled)
}

func terminateNieProcess(cmd *exec.Cmd, waitCh <-chan error, logs *lockedBuffer) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
		return nil
	}

	_ = cmd.Process.Signal(os.Interrupt)

	select {
	case err := <-waitCh:
		return err
	case <-time.After(2 * time.Second):
	}

	_ = cmd.Process.Kill()

	select {
	case err := <-waitCh:
		return err
	case <-time.After(2 * time.Second):
	}

	if logs != nil {
		return fmt.Errorf("timed out waiting for process exit; logs=%s", logs.String())
	}
	return fmt.Errorf("timed out waiting for process exit")
}

func nieRedirectInstalled() (bool, error) {
	conn := &nftables.Conn{}

	tables, err := conn.ListTables()
	if err != nil {
		return false, err
	}

	tablePresent := false
	for _, table := range tables {
		if table != nil && table.Family == nftables.TableFamilyINet && table.Name == "nie" {
			tablePresent = true
			break
		}
	}
	if !tablePresent {
		return false, nil
	}

	chains, err := conn.ListChains()
	if err != nil {
		return false, err
	}

	for _, chain := range chains {
		if chain == nil || chain.Table == nil {
			continue
		}
		if chain.Table.Family == nftables.TableFamilyINet && chain.Table.Name == "nie" && chain.Name == "output" {
			return true, nil
		}
	}
	return false, nil
}

func cleanupStaleNieRedirectState(t *testing.T) {
	t.Helper()

	installed, err := nieRedirectInstalled()
	if err != nil {
		t.Fatalf("query nftables state before cleanup: %v", err)
	}
	if !installed {
		return
	}

	cmd := exec.Command("nft", "delete", "table", "inet", "nie")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cleanup stale nft table: %v\n%s", err, output)
	}
}
