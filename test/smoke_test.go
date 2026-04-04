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
)

func TestSmoke_AuditModeAllowsUnknownTrafficButEmitsWouldDeny(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}

	root := repoRoot(t)
	tmpDir := t.TempDir()

	binPath := resolveNieBinary(t, root, tmpDir)

	upstreamAddr := startFakeUpstream(t, "203.0.113.7")
	listenAddr := pickFreeListenAddr(t)
	httpsListenAddr := pickFreeTCPAddr(t)
	configPath := filepath.Join(tmpDir, "config.yaml")
	writeConfig(t, configPath, listenAddr, httpsListenAddr, upstreamAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, binPath, "-config", configPath)
	cmd.Dir = root

	var logs lockedBuffer
	cmd.Stdout = &logs
	cmd.Stderr = &logs

	if err := cmd.Start(); err != nil {
		t.Fatalf("start nie: %v", err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	})

	waitCh := make(chan error, 1)
	go func() {
		waitCh <- cmd.Wait()
	}()

	waitForPinnedState(t, "/sys/fs/bpf/nie", true, waitCh, &logs)
	waitForNieRedirectState(t, true, waitCh, &logs)

	queryName := "blocked.example.com."
	resp := waitForAnswer(t, listenAddr, queryName, waitCh, &logs)
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %d, want %d; logs=%s", resp.Rcode, dns.RcodeSuccess, logs.String())
	}
	if !hasIPv4Answer(resp, "203.0.113.7") {
		t.Fatalf("response answers = %#v, want A 203.0.113.7", resp.Answer)
	}

	waitForLog(t, "would_deny_dns", waitCh, &logs)
	waitForLog(t, "host=blocked.example.com", waitCh, &logs)

	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatalf("signal nie: %v", err)
	}
	if err := <-waitCh; err != nil {
		t.Fatalf("wait for nie exit: %v; logs=%s", err, logs.String())
	}

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

func writeConfig(t *testing.T, path, listenAddr, httpsListenAddr, upstreamAddr string) {
	t.Helper()

	raw := fmt.Sprintf(`mode: audit
interface: lo
dns:
  listen: %s
  upstreams:
    - %s
  mark: 4242
policy:
  default: deny
  allow:
    - github.com
https:
  listen: %s
  ports:
    - 443
`, listenAddr, upstreamAddr, httpsListenAddr)

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
