//go:build integration

package test

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/miekg/dns"

	"github.com/moolen/nie/internal/netx"
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

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen fake upstream: %v", err)
	}

	handler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		if len(req.Question) == 1 && req.Question[0].Qtype == dns.TypeA {
			resp.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{
					Name:   req.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				A: net.ParseIP(answerIP).To4(),
			}}
		}
		_ = w.WriteMsg(resp)
	})

	server := &dns.Server{
		PacketConn: pc,
		Handler:    handler,
	}

	go func() {
		_ = server.ActivateAndServe()
	}()

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.ShutdownContext(ctx)
		_ = pc.Close()
	})

	return pc.LocalAddr().String()
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
	mode            string
	iface           string
	listenAddr      string
	httpsListenAddr string
	upstreamAddr    string
	allowHosts      []string
}

func writeConfig(t *testing.T, path string, opts writeConfigOptions) {
	t.Helper()

	allowSection := ""
	for _, host := range opts.allowHosts {
		allowSection += fmt.Sprintf("    - %s\n", host)
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
https:
  listen: %s
  ports:
    - 443
    - 8443
`, opts.mode, opts.iface, opts.listenAddr, opts.upstreamAddr, allowSection, opts.httpsListenAddr)

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
