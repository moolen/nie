# nie VM Host Lifecycle E2E Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a deterministic VM integration test that proves one long-lived guest process loses and regains host-wide network access as `nie` is started, stopped, and started again.

**Architecture:** Reuse the existing Vagrant private-network fixture and VM integration harness, but add a small long-lived probe helper process whose stdout becomes the source of truth for connectivity state transitions. Refactor the current VM test helpers so a single test can start and stop `nie` multiple times while keeping the same helper process alive and asserting cleanup after each stop.

**Tech Stack:** Go, Vagrant, VirtualBox, existing `miekg/dns` VM harness, root-gated integration tests

---

## File Structure

- Create: `test/cmd/vmprobe/main.go` — long-lived probe helper that repeatedly tests DNS and TCP and emits structured log lines
- Modify: `test/vm_e2e_test.go` — reusable `nie` lifecycle harness plus the new restart/recovery VM test
- Modify: `test/smoke_test.go` — only if shared process/log helpers belong here after extracting common support
- Modify: `README.md` — document the new lifecycle validation once the test is passing

### Task 1: Add The Long-Lived VM Probe Helper

**Files:**
- Create: `test/cmd/vmprobe/main.go`

- [ ] **Step 1: Write the failing helper-focused test**

Add a small unit test file alongside the helper or in a focused test package that validates parsing and output shape, for example:

```go
func TestProbeResultFormat(t *testing.T) {
	line := formatProbeResult(probeResult{
		Kind:   "tcp",
		Target: "192.168.56.1:18080",
		Result: "success",
	})

	if !strings.Contains(line, "kind=tcp") {
		t.Fatalf("line = %q, want kind=tcp", line)
	}
}
```

- [ ] **Step 2: Run the helper test to verify it fails**

Run: `go test ./test/cmd/vmprobe/...`
Expected: FAIL because the helper package does not exist yet

- [ ] **Step 3: Write the minimal long-lived helper**

Create `test/cmd/vmprobe/main.go` with:

- config via flags for:
  - `-fixture`
  - `-proxy-dns`
  - `-upstream-dns`
  - `-allowed-host`
  - `-blocked-host`
  - `-interval`
  - `-timeout`
- a loop that on each tick performs:
  - direct TCP dial to the fixture
  - DNS A lookup for the blocked host via the upstream DNS address
  - DNS A lookup for the blocked host via the `nie` listener address
  - DNS A lookup for the allowed host via the `nie` listener address
  - learned TCP dial to the fixture after the allowed lookup
- one stable machine-readable line per result, for example:

```text
kind=tcp phase=direct target=192.168.56.1:18080 result=timeout
kind=dns phase=blocked-upstream target=blocked.vm.test result=success
kind=dns phase=blocked-proxy target=blocked.vm.test result=refused
kind=dns phase=allowed-proxy target=allowed.vm.test result=success
kind=tcp phase=learned target=192.168.56.1:18080 result=success
```

- graceful shutdown on `SIGINT`/`SIGTERM`

- [ ] **Step 4: Run the helper tests to verify they pass**

Run: `go test ./test/cmd/vmprobe/...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add test/cmd/vmprobe
git commit -m "test: add vm lifecycle probe helper"
```

### Task 2: Refactor The VM Harness For Repeated nie Start And Stop

**Files:**
- Modify: `test/vm_e2e_test.go`
- Modify: `test/smoke_test.go` only if shared helpers become cleaner there

- [ ] **Step 1: Write the failing lifecycle harness test path**

Add a new VM-only test skeleton in `test/vm_e2e_test.go`:

```go
func TestVMLongLivedProcessRecoversAcrossNieRestart(t *testing.T) {
	if os.Getenv("NIE_VM_E2E") != "1" {
		t.Skip("vm e2e disabled")
	}

	t.Fatal("not implemented")
}
```

- [ ] **Step 2: Run the VM workflow to verify it fails**

Run: `./vm/vagrant/run-vm-tests.sh`
Expected: FAIL at `TestVMLongLivedProcessRecoversAcrossNieRestart`

- [ ] **Step 3: Refactor the existing VM harness into restartable pieces**

In `test/vm_e2e_test.go`, introduce minimal reusable helpers so one test can:

- build one `nie` config for the VM interface
- start `nie` and wait for redirect/bpffs state
- stop `nie` and wait for cleanup
- restart `nie` with the same config and fresh `exec.Cmd`
- keep fixture settings and DNS settings stable across cycles

Concretely, replace the single-shot `startVMNieScenario(...).stopAndWait(...)` shape with a small reusable runner type, for example:

```go
type vmNieHarness struct {
	root       string
	binPath     string
	configPath  string
	listenAddr  string
	fixture     vmFixture
	allowedHost string
	blockedHost string
}

func (h *vmNieHarness) start(t *testing.T) *vmNieRun
func (h *vmNieHarness) stop(t *testing.T, run *vmNieRun)
```

- [ ] **Step 4: Re-run the existing VM suite to verify no regression before adding the new test body**

Run: `go test -tags=integration ./test/... -run 'TestVM(Enforce|Audit)|TestSmoke' -v`
Expected: PASS for the existing VM tests after the harness refactor

- [ ] **Step 5: Re-run the new lifecycle test to verify it is still the one failing**

Run: `go test -tags=integration ./test/... -run TestVMLongLivedProcessRecoversAcrossNieRestart -v`
Expected: FAIL at the explicit lifecycle assertions or `not implemented` path

- [ ] **Step 6: Commit**

```bash
git add test/vm_e2e_test.go test/smoke_test.go
git commit -m "test: refactor vm harness for nie restart cycles"
```

### Task 3: Add The Long-Lived Host Lifecycle VM Test

**Files:**
- Modify: `test/vm_e2e_test.go`
- Create or modify support under: `test/cmd/vmprobe/...`

- [ ] **Step 1: Write the full failing lifecycle test**

Implement `TestVMLongLivedProcessRecoversAcrossNieRestart` to:

- start the long-lived helper process before `nie`
- assert baseline success lines from the helper
- start `nie` in `enforce`
- wait for helper evidence that:
  - direct TCP is blocked
  - blocked DNS is refused
- confirm allowed DNS success and learned TCP success
- stop `nie`
- wait for helper evidence that:
  - blocked DNS recovers to success
  - direct TCP recovers to success
- repeat the full start-stop sequence a second time with the same helper process
- finally stop the helper and assert it exited cleanly

- [ ] **Step 2: Run the VM workflow to verify the new test fails for the right reason**

Run: `./vm/vagrant/run-vm-tests.sh`
Expected: FAIL with lifecycle-state assertions until the helper orchestration is complete

- [ ] **Step 3: Implement the minimal lifecycle orchestration**

Extend `test/vm_e2e_test.go` with helpers to:

- build the `vmprobe` binary from the repo
- start it as one long-lived process
- capture its stdout in a locked buffer
- wait for sustained helper states, for example:

```go
func waitForProbeState(t *testing.T, logs *lockedBuffer, needles ...string)
func waitForProbeStateNTimes(t *testing.T, logs *lockedBuffer, n int, needles ...string)
```

Suggested assertions per cycle:

- baseline:
  - `kind=tcp phase=direct result=success`
  - `kind=dns phase=blocked-upstream result=success`
- `nie` enforcing:
  - `kind=tcp phase=direct result=timeout` or `result=error`
  - `kind=dns phase=blocked-proxy result=refused`
- after allowed learning:
  - `kind=dns phase=allowed-proxy result=success`
  - `kind=tcp phase=learned result=success`
- after `nie` stop:
  - `kind=dns phase=blocked-upstream result=success`
  - `kind=tcp phase=direct result=success`

Keep the cleanup checks after each stop:

- `waitForVMPinnedStateAfterExit(t, "/sys/fs/bpf/nie", false)`
- `waitForVMNieRedirectStateAfterExit(t, false)`

- [ ] **Step 4: Run the VM workflow to verify it passes**

Run: `./vm/vagrant/run-vm-tests.sh`
Expected: PASS with the new lifecycle test included

- [ ] **Step 5: Run the broader package suite**

Run: `go test ./...`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add test/vm_e2e_test.go test/cmd/vmprobe
git commit -m "test: add vm host lifecycle restart coverage"
```

### Task 4: Document The New Lifecycle Validation

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Verify the README does not mention lifecycle restart coverage yet**

Run: `rg -n 'long-lived|restart|recovery|host-wide|lifecycle' README.md`
Expected: either no relevant matches or no mention of repeated start-stop lifecycle validation

- [ ] **Step 2: Add the minimal documentation update**

Document that the VM suite now also validates:

- one long-lived guest process losing host-wide egress while `nie` is active
- that same process regaining DNS and TCP after `nie` shuts down
- repeatable `nie` start-stop cleanup on the VM host path

- [ ] **Step 3: Re-run verification**

Run: `go test ./...`
Expected: PASS

Run: `./vm/vagrant/run-vm-tests.sh`
Expected: PASS

Run: `rg -n 'long-lived|restart|recovery|host-wide|lifecycle' README.md`
Expected: PASS with the new documentation lines

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: describe vm lifecycle restart coverage"
```
