//go:build integration

package test

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/vishvananda/netlink"
)

func TestVMEnforceBlocksThenAllowsRealEgress(t *testing.T) {
	harness := newVMNieHarness(t, vmScenario{mode: "enforce"})
	run := harness.start(t)

	assertFixtureBlockedBeforeLearning(t, run.fixture.Address, run.waitCh, run.logs)

	resp := waitForAnswer(t, run.listenAddr, run.allowedHost+".", run.waitCh, run.logs)
	assertFixtureLearned(t, resp, run.fixture.IP)

	waitForFixtureReachable(t, run.fixture.Address, run.waitCh, run.logs)

	harness.stop(t, run)
}

func TestVMEnforceDeniedHostnameReturnsRefused(t *testing.T) {
	harness := newVMNieHarness(t, vmScenario{
		mode: "enforce",
	})
	run := harness.start(t)

	resp := waitForAnswer(t, run.listenAddr, "blocked.vm.test.", run.waitCh, run.logs)
	if resp.Rcode != dns.RcodeRefused {
		t.Fatalf("rcode = %d, want %d", resp.Rcode, dns.RcodeRefused)
	}

	harness.stop(t, run)
}

func TestVMAuditLogsWouldDenyDNSAndEgress(t *testing.T) {
	harness := newVMNieHarness(t, vmScenario{
		mode: "audit",
	})
	run := harness.start(t)

	waitForFixtureReachable(t, run.fixture.Address, run.waitCh, run.logs)
	waitForLogLine(t, run.waitCh, run.logs, "would_deny_egress", "dst="+run.fixture.IP)

	resp := waitForAnswer(t, run.listenAddr, "blocked.vm.test.", run.waitCh, run.logs)
	assertFixtureLearned(t, resp, run.fixture.IP)
	waitForLog(t, "would_deny_dns", run.waitCh, run.logs)
	waitForLog(t, "host=blocked.vm.test", run.waitCh, run.logs)

	harness.stop(t, run)
}

func TestVMLongLivedProcessRecoversAcrossNieRestart(t *testing.T) {
	if os.Getenv("NIE_VM_E2E") != "1" {
		t.Skip("vm e2e disabled")
	}

	t.Fatal("not implemented")
}

type vmFixture struct {
	Address string
	IP      string
	Port    string
}

type vmScenario struct {
	mode       string
	allowHosts []string
}

type vmNieHarness struct {
	root        string
	binPath     string
	configPath  string
	listenAddr  string
	fixture     vmFixture
	allowedHost string
}

type vmRun struct {
	fixture     vmFixture
	allowedHost string
	listenAddr  string
	logs        *lockedBuffer
	waitCh      <-chan error
	procDone    <-chan struct{}
	cmd         *exec.Cmd
	stopped     bool
}

func newVMNieHarness(t *testing.T, scenario vmScenario) *vmNieHarness {
	t.Helper()

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
	if scenario.mode == "" {
		scenario.mode = "enforce"
	}
	if len(scenario.allowHosts) == 0 {
		scenario.allowHosts = []string{allowedHost}
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
	writeVMConfig(t, configPath, scenario.mode, iface, listenAddr, upstreamAddr, scenario.allowHosts)

	return &vmNieHarness{
		root:        root,
		binPath:     binPath,
		configPath:  configPath,
		listenAddr:  listenAddr,
		fixture:     fixture,
		allowedHost: allowedHost,
	}
}

func (h *vmNieHarness) start(t *testing.T) *vmRun {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	cmd := exec.CommandContext(ctx, h.binPath, "-config", h.configPath)
	cmd.Dir = h.root

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

	run := &vmRun{
		fixture:     h.fixture,
		allowedHost: h.allowedHost,
		listenAddr:  h.listenAddr,
		logs:        &logs,
		waitCh:      waitCh,
		procDone:    procDone,
		cmd:         cmd,
	}

	t.Cleanup(func() {
		if !run.stopped {
			gracefulStopVMNie(cmd, procDone)
		}
	})

	waitForPinnedState(t, "/sys/fs/bpf/nie", true, waitCh, &logs)
	waitForNieRedirectState(t, true, waitCh, &logs)

	return run
}

func (h *vmNieHarness) stop(t *testing.T, run *vmRun) {
	t.Helper()

	if run == nil || run.cmd == nil || run.cmd.Process == nil {
		t.Fatal("nie process is not running")
	}
	if run.stopped {
		return
	}
	run.stopped = true

	if err := run.cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatalf("signal nie: %v", err)
	}
	forced, err := waitForVMNieExit(run.cmd, run.waitCh, run.procDone, 2*time.Second, 2*time.Second)
	if err != nil && !forced {
		t.Fatalf("wait for nie exit: %v; logs=%s", err, run.logs.String())
	}
	if err != nil && forced {
		t.Logf("nie killed after timeout: %v", err)
	}

	waitForVMPinnedStateAfterExit(t, "/sys/fs/bpf/nie", false)
	waitForVMNieRedirectStateAfterExit(t, false)
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

func writeVMConfig(t *testing.T, path, mode, iface, listenAddr, upstreamAddr string, allowHosts []string) {
	t.Helper()

	allowSection := ""
	for _, host := range allowHosts {
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
%s`, mode, iface, listenAddr, upstreamAddr, allowSection)

	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatalf("write vm config: %v", err)
	}
}

func waitForLogLine(t *testing.T, waitCh <-chan error, logs *lockedBuffer, needles ...string) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, line := range strings.Split(logs.String(), "\n") {
			if logLineContainsAll(line, needles...) {
				return
			}
		}

		select {
		case err := <-waitCh:
			t.Fatalf("nie exited before log line %q: %v; logs=%s", strings.Join(needles, " "), err, logs.String())
		default:
		}

		time.Sleep(100 * time.Millisecond)
	}

	t.Fatalf("timed out waiting for log line %q; logs=%s", strings.Join(needles, " "), logs.String())
}

func logLineContainsAll(line string, needles ...string) bool {
	for _, needle := range needles {
		if !strings.Contains(line, needle) {
			return false
		}
	}
	return true
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

func waitForVMNieExit(cmd *exec.Cmd, waitCh <-chan error, procDone <-chan struct{}, interruptTimeout, killTimeout time.Duration) (bool, error) {
	select {
	case err := <-waitCh:
		return false, err
	case <-time.After(interruptTimeout):
	}

	select {
	case <-procDone:
		return false, nil
	default:
	}

	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}

	return true, waitForVMNieKill(waitCh, procDone, killTimeout)
}

func waitForVMNieKill(waitCh <-chan error, procDone <-chan struct{}, killTimeout time.Duration) error {
	select {
	case err := <-waitCh:
		return err
	case <-time.After(killTimeout):
	}

	select {
	case <-procDone:
		return nil
	default:
	}

	return fmt.Errorf("timed out waiting for nie to exit after kill")
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
