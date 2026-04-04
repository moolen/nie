//go:build integration

package test

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/vishvananda/netlink"
)

func TestVMEnforceBlocksThenAllowsRealEgress(t *testing.T) {
	if os.Getenv("NIE_VM_E2E") != "1" {
		t.Skip("vm e2e disabled")
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}

	fixtureAddr := os.Getenv("NIE_VM_FIXTURE_ADDR")
	allowedHost := os.Getenv("NIE_VM_ALLOWED_HOST")
	if fixtureAddr == "" || allowedHost == "" {
		t.Fatal("missing vm e2e environment")
	}

	root := repoRoot(t)
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "nie")
	buildNieBinary(t, root, binPath)

	fixture := parseVMFixture(t, fixtureAddr)
	iface := routeInterfaceFor(t, fixture.IP)
	listenAddr := pickFreeListenAddr(t)
	upstreamAddr := startFakeUpstream(t, fixture.IP)
	configPath := filepath.Join(tmpDir, "config.yaml")
	writeVMConfig(t, configPath, iface, listenAddr, upstreamAddr, allowedHost)

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

	waitCh := make(chan error, 1)
	procDone := make(chan struct{})
	go func() {
		waitCh <- cmd.Wait()
		close(procDone)
	}()

	t.Cleanup(func() {
		gracefulStopVMNie(cmd, procDone)
	})

	waitForPinnedState(t, "/sys/fs/bpf/nie", true, waitCh, &logs)
	waitForNieRedirectState(t, true, waitCh, &logs)

	assertFixtureBlockedBeforeLearning(t, fixture.Address, waitCh, &logs)

	resp := waitForAnswer(t, listenAddr, allowedHost+".", waitCh, &logs)
	assertFixtureLearned(t, resp, fixture.IP)

	waitForFixtureReachable(t, fixture.Address, waitCh, &logs)

	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatalf("signal nie: %v", err)
	}
	if err := <-waitCh; err != nil {
		t.Fatalf("wait for nie exit: %v; logs=%s", err, logs.String())
	}

	waitForVMPinnedStateAfterExit(t, "/sys/fs/bpf/nie", false)
	waitForVMNieRedirectStateAfterExit(t, false)
}

type vmFixture struct {
	Address string
	IP      string
	Port    string
}

func parseVMFixture(t *testing.T, raw string) vmFixture {
	t.Helper()

	host, port, err := net.SplitHostPort(raw)
	if err != nil {
		t.Fatalf("split fixture address %q: %v", raw, err)
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() == nil {
		t.Fatalf("fixture host %q is not a valid IPv4 address", host)
	}

	return vmFixture{
		Address: raw,
		IP:      ip.String(),
		Port:    port,
	}
}

func routeInterfaceFor(t *testing.T, rawIP string) string {
	t.Helper()

	ip := net.ParseIP(rawIP)
	if ip == nil {
		t.Fatalf("parse route target IP %q", rawIP)
	}

	routes, err := netlink.RouteGet(ip)
	if err != nil {
		t.Fatalf("route get %s: %v", rawIP, err)
	}
	if len(routes) == 0 {
		t.Fatalf("no route to %s", rawIP)
	}

	for _, route := range routes {
		if route.LinkIndex == 0 {
			continue
		}
		link, err := netlink.LinkByIndex(route.LinkIndex)
		if err != nil {
			t.Fatalf("link by index %d: %v", route.LinkIndex, err)
		}
		iface := link.Attrs().Name
		if iface == "" {
			t.Fatalf("route interface for %s is empty", rawIP)
		}
		if iface == "lo" {
			t.Fatalf("route to %s resolved to loopback interface", rawIP)
		}
		return iface
	}

	t.Fatalf("no route with link index to %s", rawIP)
	return ""
}

func writeVMConfig(t *testing.T, path, iface, listenAddr, upstreamAddr, allowedHost string) {
	t.Helper()

	raw := fmt.Sprintf(`mode: enforce
interface: %s
dns:
  listen: %s
  upstreams:
    - %s
  mark: 4242
policy:
  default: deny
  allow:
    - %s
`, iface, listenAddr, upstreamAddr, allowedHost)

	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatalf("write vm config: %v", err)
	}
}

func assertFixtureBlockedBeforeLearning(t *testing.T, fixtureAddr string, waitCh <-chan error, logs *lockedBuffer) {
	t.Helper()

	deadline := time.Now().Add(3 * time.Second)
	consecutiveFailures := 0

	for time.Now().Before(deadline) {
		select {
		case err := <-waitCh:
			t.Fatalf("nie exited before blocked-egress assertion: %v; logs=%s", err, logs.String())
		default:
		}

		if err := dialFixture(fixtureAddr, 250*time.Millisecond); err != nil {
			consecutiveFailures++
			if consecutiveFailures >= 5 {
				return
			}
		} else {
			consecutiveFailures = 0
		}

		time.Sleep(100 * time.Millisecond)
	}

	t.Fatalf("direct egress to fixture %s did not show sustained pre-learn blocking; logs=%s", fixtureAddr, logs.String())
}

func assertFixtureLearned(t *testing.T, resp *dns.Msg, fixtureIP string) {
	t.Helper()

	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %d, want %d", resp.Rcode, dns.RcodeSuccess)
	}
	if !hasIPv4Answer(resp, fixtureIP) {
		t.Fatalf("response answers = %#v, want A %s", resp.Answer, fixtureIP)
	}
}

func waitForFixtureReachable(t *testing.T, fixtureAddr string, waitCh <-chan error, logs *lockedBuffer) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-waitCh:
			t.Fatalf("nie exited before fixture egress succeeded: %v; logs=%s", err, logs.String())
		default:
		}

		if err := dialFixture(fixtureAddr, time.Second); err == nil {
			return
		}

		time.Sleep(100 * time.Millisecond)
	}

	t.Fatalf("timed out waiting for fixture %s to become reachable; logs=%s", fixtureAddr, logs.String())
}

func dialFixture(addr string, timeout time.Duration) error {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return err
	}
	return conn.Close()
}

func gracefulStopVMNie(cmd *exec.Cmd, procDone <-chan struct{}) {
	if cmd == nil || cmd.Process == nil {
		return
	}

	select {
	case <-procDone:
		return
	default:
	}

	_ = cmd.Process.Signal(os.Interrupt)

	select {
	case <-procDone:
		return
	case <-time.After(2 * time.Second):
	}

	_ = cmd.Process.Kill()

	select {
	case <-procDone:
	case <-time.After(2 * time.Second):
	}
}

func waitForVMPinnedStateAfterExit(t *testing.T, path string, wantExists bool) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		_, err := os.Stat(path)
		exists := err == nil
		if exists == wantExists {
			return
		}
		if err != nil && !os.IsNotExist(err) {
			t.Fatalf("stat %s: %v", path, err)
		}
		time.Sleep(100 * time.Millisecond)
	}

	t.Fatalf("timed out waiting after vm exit for pinned state at %s to be exists=%t", path, wantExists)
}

func waitForVMNieRedirectStateAfterExit(t *testing.T, wantInstalled bool) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		installed, err := nieRedirectInstalled()
		if err != nil {
			t.Fatalf("query nftables state: %v", err)
		}
		if installed == wantInstalled {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}

	t.Fatalf("timed out waiting after vm exit for nftables redirect state installed=%t", wantInstalled)
}
