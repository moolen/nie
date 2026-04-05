# nie Architecture Reshape Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract a dedicated application composition root so runtime architecture and data flow are explicit, while preserving current behavior.

**Architecture:** Move runtime assembly, preflight checks, DNS adapters, and audit logger lifecycle into a new `internal/app` package. Keep `cmd/nie` as a thin CLI/process shell and keep `internal/runtime` as the ordered lifecycle executor. Preserve existing startup order `EBPF -> DNS -> HTTPS -> Redirect` and reverse stop order.

**Tech Stack:** Go, stdlib `context/net/log/slog`, existing `internal/*` packages, existing unit tests, privileged smoke/VM validation

---

### Task 1: Create `internal/app` Package Skeleton

**Files:**
- Create: `internal/app/run.go`
- Create: `internal/app/build.go`
- Create: `internal/app/dns.go`
- Create: `internal/app/audit.go`
- Create: `internal/app/preflight.go`
- Create: `internal/app/app_test.go`

- [ ] **Step 1: Write the failing package-level scaffolding test**

Add a test in `internal/app/app_test.go` that imports the new package and
references the intended top-level API shape, for example `Run(...)` and a
runtime-build helper. The goal is to force the package and public-internal API
to exist.

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/app -run TestAppPackageScaffold -count=1`

Expected: build failure because the package or symbols do not yet exist.

- [ ] **Step 3: Add the minimal package skeleton**

Create the new files with placeholder type/function declarations only:

- `Run(ctx context.Context, cfg config.Config, logger *slog.Logger) error`
- internal helper placeholders for build/preflight/audit/DNS adapters

Do not move behavior yet.

- [ ] **Step 4: Run the scaffold test again**

Run: `go test ./internal/app -run TestAppPackageScaffold -count=1`

Expected: PASS.

### Task 2: Move Preflight Validation Into `internal/app`

**Files:**
- Modify: `cmd/nie/main.go`
- Modify: `cmd/nie/main_test.go`
- Modify: `internal/app/preflight.go`
- Modify: `internal/app/app_test.go`

- [ ] **Step 1: Write failing tests for interface validation in `internal/app`**

Move or recreate the current IPv6 fail-closed coverage in `internal/app` tests:

- success path with IPv4-only addresses
- failure path with IPv6 assigned
- unsupported address type handling

- [ ] **Step 2: Run the targeted tests to verify they fail**

Run: `go test ./internal/app -run 'TestValidateProtectedInterface' -count=1`

Expected: FAIL because the validation helpers are not yet implemented there.

- [ ] **Step 3: Implement the validation helpers in `internal/app/preflight.go`**

Move:

- interface lookup
- address listing
- IPv6 fail-closed logic
- address parsing helper

Keep logic behavior-identical to current `cmd/nie` behavior.

- [ ] **Step 4: Re-run the targeted tests**

Run: `go test ./internal/app -run 'TestValidateProtectedInterface' -count=1`

Expected: PASS.

- [ ] **Step 5: Remove duplicate preflight code from `cmd/nie`**

Delete the moved validation helpers from `cmd/nie/main.go` after app tests pass.

### Task 3: Move Audit Egress Logger Lifecycle Into `internal/app`

**Files:**
- Modify: `cmd/nie/main.go`
- Modify: `cmd/nie/main_test.go`
- Modify: `internal/app/audit.go`
- Modify: `internal/app/app_test.go`

- [ ] **Step 1: Write failing `internal/app` tests for audit logger behavior**

Port the current audit logger tests to `internal/app`:

- logs allow events in audit mode
- ignores drop events
- closes reader on shutdown
- preserves rollback semantics when startup fails

- [ ] **Step 2: Run the targeted tests to verify they fail**

Run: `go test ./internal/app -run 'Test(StartAuditEgressLogger|LogAuditEgressEvents)' -count=1`

Expected: FAIL because the helpers are not yet moved.

- [ ] **Step 3: Implement `internal/app/audit.go`**

Move:

- audit event reader startup
- goroutine lifecycle
- close-and-drain shutdown behavior
- audit log formatting

Do not change event semantics.

- [ ] **Step 4: Re-run the targeted tests**

Run: `go test ./internal/app -run 'Test(StartAuditEgressLogger|LogAuditEgressEvents)' -count=1`

Expected: PASS.

- [ ] **Step 5: Remove duplicate audit helpers from `cmd/nie/main.go`**

After the moved tests pass, delete the old implementations from `cmd/nie`.

### Task 4: Move DNS Adapters Into `internal/app`

**Files:**
- Modify: `cmd/nie/main.go`
- Modify: `cmd/nie/main_test.go`
- Modify: `internal/app/dns.go`
- Modify: `internal/app/app_test.go`

- [ ] **Step 1: Write failing tests for app-scoped DNS adapters**

Port the existing tests for:

- UDP bind failure
- TCP bind failure cleanup
- stop continues after one server shutdown error
- DNS upstream exchange adapter behavior

Target them at `internal/app`.

- [ ] **Step 2: Run the targeted tests to verify they fail**

Run: `go test ./internal/app -run 'Test(DNSListenerLifecycle|DNSClientUpstream)' -count=1`

Expected: FAIL because the adapters are not yet defined in `internal/app`.

- [ ] **Step 3: Implement `internal/app/dns.go`**

Move:

- `dnsListenerLifecycle`
- DNS upstream adapter using the marked dialer
- small adapter-local interfaces (`dnsServer`, upstream wrapper)

Keep `internal/dnsproxy` unchanged and focused on handler logic only.

- [ ] **Step 4: Re-run the targeted tests**

Run: `go test ./internal/app -run 'Test(DNSListenerLifecycle|DNSClientUpstream)' -count=1`

Expected: PASS.

### Task 5: Move Runtime Assembly Into `internal/app/build.go`

**Files:**
- Modify: `cmd/nie/main.go`
- Modify: `cmd/nie/main_test.go`
- Modify: `internal/app/build.go`
- Modify: `internal/app/app_test.go`

- [ ] **Step 1: Write failing application assembly tests**

Move or recreate the current assembly-focused tests in `internal/app`:

- build succeeds with live trust writer delegation
- marked dialer constructor failure is wrapped
- redirect constructor failure is wrapped
- interface validation failure is wrapped

- [ ] **Step 2: Run the targeted tests to verify they fail**

Run: `go test ./internal/app -run 'Test(BuildRuntimeService|BuildComponents)' -count=1`

Expected: FAIL because runtime assembly still lives in `cmd/nie`.

- [ ] **Step 3: Implement `internal/app/build.go`**

Move:

- builder/test seam type currently in `cmd/nie`
- runtime assembly helper(s)
- config-to-component translation
- policy/trust-plan/HTTP-policy wiring
- CA/cache/proxy/service wiring
- redirect/eBPF manager wiring
- DNS handler/listener wiring

Keep the data flow top-to-bottom and explicit. Do not move domain logic out of
existing lower-level packages.

- [ ] **Step 4: Re-run the targeted tests**

Run: `go test ./internal/app -run 'Test(BuildRuntimeService|BuildComponents)' -count=1`

Expected: PASS.

### Task 6: Move High-Level Run Orchestration Into `internal/app/run.go`

**Files:**
- Modify: `cmd/nie/main.go`
- Modify: `cmd/nie/main_test.go`
- Modify: `internal/app/run.go`
- Modify: `internal/app/app_test.go`

- [ ] **Step 1: Write failing orchestration tests in `internal/app`**

Cover:

- successful lifecycle start and stop on context cancellation
- audit logger startup only in audit mode
- audit logger startup failure triggers lifecycle rollback
- stop context is used during shutdown

- [ ] **Step 2: Run the targeted tests to verify they fail**

Run: `go test ./internal/app -run 'TestRun' -count=1`

Expected: FAIL because orchestration still lives in `cmd/nie`.

- [ ] **Step 3: Implement `internal/app/run.go`**

Move:

- top-level `run(...)` logic
- stop-context factory seam
- integration of runtime service and audit logger lifecycle

Preserve behavior:

- same startup order through `internal/runtime`
- same rollback on startup failure
- same stop behavior on cancellation

- [ ] **Step 4: Re-run the targeted tests**

Run: `go test ./internal/app -run 'TestRun' -count=1`

Expected: PASS.

### Task 7: Reduce `cmd/nie` To CLI-Only Shell

**Files:**
- Modify: `cmd/nie/main.go`
- Modify: `cmd/nie/main_test.go`

- [ ] **Step 1: Write or adjust CLI-focused tests**

Retain only CLI/process-shell coverage in `cmd/nie`:

- missing `-config`
- config read failure
- config load failure
- `app.Run` error propagation, if a seam is kept for testing

- [ ] **Step 2: Run the targeted CLI tests to verify the desired thin shell**

Run: `go test ./cmd/nie -run 'Test(Main|CLI)' -count=1`

Expected: either FAIL because old tests still reference moved internals, or PASS
after the test suite is reduced to CLI-only concerns.

- [ ] **Step 3: Simplify `cmd/nie/main.go`**

Leave only:

- flag parsing
- config file read/load
- logger creation
- signal context creation
- call to `app.Run(...)`
- process exit handling

- [ ] **Step 4: Re-run CLI tests**

Run: `go test ./cmd/nie -count=1`

Expected: PASS.

### Task 8: Verify Behavior Preservation

**Files:**
- No new source files required

- [ ] **Step 1: Run focused package tests**

Run: `go test ./internal/app ./internal/mitm ./internal/dnsproxy ./internal/runtime ./cmd/nie -count=1`

Expected: PASS.

- [ ] **Step 2: Run broader non-privileged package tests**

Run: `go test ./internal/config ./internal/dnsproxy ./internal/ebpf ./internal/httppolicy ./internal/policy ./internal/runtime ./internal/app ./cmd/nie -count=1`

Expected: PASS.

- [ ] **Step 3: Run one privileged validation path**

Preferred:

- `./vm/vagrant/run-vm-tests.sh`

Fallback if VM is intentionally skipped:

- `sudo -E go test -tags=integration ./test/... -count=1`

Expected: PASS, demonstrating the refactor preserved runtime behavior.

- [ ] **Step 4: Review the final diff for scope**

Confirm the refactor:

- moved composition/wiring concerns into `internal/app`
- kept lower-level package logic in place
- reduced `cmd/nie` to CLI-only concerns
- preserved lifecycle order and audit behavior

- [ ] **Step 5: Commit**

```bash
git add cmd/nie internal/app docs/superpowers/specs/2026-04-05-nie-architecture-reshape-design.md docs/superpowers/plans/2026-04-05-nie-architecture-reshape.md
git commit -m "refactor: extract app composition root"
```
