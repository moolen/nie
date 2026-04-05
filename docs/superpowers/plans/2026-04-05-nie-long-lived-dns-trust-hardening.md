# Long-Lived DNS Trust Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add operator-tunable trust cleanup settings and prove end to end that DNS rotation preserves active TCP flows while eventually removing stale trusted IPs after drain.

**Architecture:** Extend the typed config surface with a top-level `trust:` block, wire those values into the shared `trustsync.Service`, and harden the integration harness with a deterministic rotating fake upstream plus a persistent TCP-flow probe. Keep defaults backward-compatible by preserving current trustsync behavior when the config block is omitted.

**Tech Stack:** Go, YAML config loading, existing `trustsync` lifecycle, root-gated integration tests, `miekg/dns`

---

### Task 1: Add Trust Config Surface And Validation

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/config/config_test.go`
- Test: `internal/config/config_test.go`

- [ ] **Step 1: Write the failing config acceptance test**

Add a new test in `internal/config/config_test.go` that loads:

```yaml
mode: enforce
interface: eth0
dns:
  listen: 127.0.0.1:1053
  upstreams: [1.1.1.1:53]
  mark: 4242
policy:
  default: deny
  allow: ["github.com"]
trust:
  max_stale_hold: 2m
  sweep_interval: 15s
https:
  ports: [443]
```

Assert:

- `cfg.Trust.MaxStaleHold == 2*time.Minute`
- `cfg.Trust.SweepInterval == 15*time.Second`

- [ ] **Step 2: Run the new test to verify RED**

Run: `go test ./internal/config -run 'TestLoadConfig_(AcceptsTrustDurations|Valid)$' -count=1`

Expected: FAIL because `Config` does not yet expose a `Trust` block or duration parsing.

- [ ] **Step 3: Write failing validation tests for bad trust durations**

Add table-driven tests in `internal/config/config_test.go` covering:

- invalid duration syntax for `trust.max_stale_hold`
- invalid duration syntax for `trust.sweep_interval`
- negative `trust.max_stale_hold`
- negative `trust.sweep_interval`

Check that error strings mention the exact field names.

- [ ] **Step 4: Run the invalid-duration tests to verify RED**

Run: `go test ./internal/config -run 'TestLoadConfig_RejectsInvalidTrust' -count=1`

Expected: FAIL because trust validation does not exist yet.

- [ ] **Step 5: Implement the typed trust config**

In `internal/config/config.go`:

- add a top-level field to `Config`

```go
Trust Trust `yaml:"trust"`
```

- add a typed struct

```go
type Trust struct {
	MaxStaleHold  time.Duration `yaml:"max_stale_hold"`
	SweepInterval time.Duration `yaml:"sweep_interval"`
}
```

- import `time`
- rely on YAML unmarshalling for Go duration strings
- add validation in `(*Config).Validate()`:
  - reject `c.Trust.MaxStaleHold < 0`
  - reject `c.Trust.SweepInterval < 0`
  - use field-specific error text: `trust.max_stale_hold` / `trust.sweep_interval`

- [ ] **Step 6: Run the focused config suite to verify GREEN**

Run: `go test ./internal/config -count=1`

Expected: PASS.

- [ ] **Step 7: Commit the config surface**

Run:

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat: add trust cleanup config"
```

### Task 2: Wire Trust Settings Into Runtime Construction

**Files:**
- Modify: `internal/app/build.go`
- Modify: `internal/app/app_test.go`
- Test: `internal/app/app_test.go`

- [ ] **Step 1: Write the failing runtime wiring test**

Add a test in `internal/app/app_test.go` that:

- uses `testConfig(t)`
- sets:

```go
cfg.Trust.MaxStaleHold = 2 * time.Minute
cfg.Trust.SweepInterval = 15 * time.Second
```

- calls `buildComponents(...)`
- asserts the returned `svc.Trust.(*trustsync.Service)` preserves those settings by observing behavior:
  - a stale UDP destination is not pruned before `MaxStaleHold`
  - the shared service instance is still used by the reconciler

Prefer a behavior assertion over reaching into unexported fields.

- [ ] **Step 2: Run the new runtime wiring test to verify RED**

Run: `go test ./internal/app -run 'TestBuildComponentsUsesConfiguredTrustCleanupTiming' -count=1`

Expected: FAIL because `buildRuntimeService` currently constructs `trustsync.New(...)` with only the deleter.

- [ ] **Step 3: Implement runtime wiring**

In `internal/app/build.go`, update:

```go
trustService := trustsync.New(trustsync.ServiceConfig{
    MaxStaleHold:  cfg.Trust.MaxStaleHold,
    SweepInterval: cfg.Trust.SweepInterval,
    Deleter:       liveTrustDeleter{source: ebpfMgr},
})
```

Keep the rest of the reconciler and deleter wiring unchanged.

- [ ] **Step 4: Run the focused app tests to verify GREEN**

Run: `go test ./internal/app -count=1`

Expected: PASS.

- [ ] **Step 5: Commit the runtime wiring**

Run:

```bash
git add internal/app/build.go internal/app/app_test.go
git commit -m "feat: wire trust cleanup config into runtime"
```

### Task 3: Add Deterministic DNS Rotation And Flow-Drain Integration Coverage

**Files:**
- Modify: `test/smoke_test.go`
- Modify: `test/integration_probes_test.go`
- Test: `test/smoke_test.go`

- [ ] **Step 1: Write the failing integration test**

Add `TestSmoke_EnforceKeepsActiveTCPFlowAcrossDNSRotationAndEventuallyPrunesStaleIP` in `test/smoke_test.go`.

Test outline:

```go
fixtureA := startIntegrationFixture(t, "127.0.0.2")
fixtureB := startIntegrationFixture(t, "127.0.0.3")
upstream := startRotatingFakeUpstream(t, fixtureA.IP)
writeConfig(..., writeConfigOptions{
    mode: "enforce",
    iface: "lo",
    listenAddr: listenAddr,
    httpsListenAddr: httpsListenAddr,
    upstreamAddr: upstream.Addr(),
    allowHosts: []string{"allowed.example.com"},
    trustMaxStaleHold: "0s",
    trustSweepInterval: "100ms",
})
```

Then:

1. start `nie`
2. learn IP A with `waitForMarkedAnswer(...)`
3. open a persistent TCP flow to `fixtureTCPEchoAddr(fixtureA.IP)`
4. rotate the fake upstream to IP B
5. learn IP B with a second DNS query
6. verify:
   - new connections to B succeed
   - the existing persistent connection to A still succeeds
7. close the persistent connection
8. wait until fresh TCP probes to A return `error` or `timeout`

- [ ] **Step 2: Add the failing helper scaffolding**

In `test/integration_probes_test.go` and `test/smoke_test.go`, add test uses for helpers that do not exist yet:

- `startRotatingFakeUpstream(...)`
- `(*rotatingFakeUpstream).SetAnswerIP(...)`
- `persistentTCPFlow(...)` or equivalent helper pair:
  - open once
  - send probe payload repeatedly over the same connection
  - close explicitly

- [ ] **Step 3: Run the single integration test to verify RED**

Run: `go test -tags=integration ./test -run TestSmoke_EnforceKeepsActiveTCPFlowAcrossDNSRotationAndEventuallyPrunesStaleIP -count=1`

Expected: FAIL because the rotation and persistent-flow helpers do not exist yet.

- [ ] **Step 4: Implement rotating upstream support**

In `test/smoke_test.go`, replace the fixed single-IP helper pattern with a deterministic rotatable helper, for example:

```go
type rotatingFakeUpstream struct {
    mu       sync.RWMutex
    answerIP string
    server   *dns.Server
    pc       net.PacketConn
}
```

Expose:

- `Addr() string`
- `SetAnswerIP(string)`

Keep `startFakeUpstream(t, answerIP string)` as a thin wrapper around the new helper if that reduces churn in existing tests.

- [ ] **Step 5: Implement persistent TCP flow probing**

In `test/integration_probes_test.go`, add a helper that:

- opens one TCP connection
- writes `integrationProbePayload`
- reads the echoed payload
- allows repeating that exchange on the same connection under deadlines
- exposes `Close() error`

Example shape:

```go
type persistentTCPEchoProbe struct {
    conn net.Conn
}

func startPersistentTCPEchoProbe(target string, timeout time.Duration) (*persistentTCPEchoProbe, error)
func (p *persistentTCPEchoProbe) Exchange(timeout time.Duration) string
func (p *persistentTCPEchoProbe) Close() error
```

- [ ] **Step 6: Make the new integration test pass**

Use `waitForProbeResults(...)` for eventual assertions and keep the existing process cleanup pattern:

- wait for pinned BPF state
- wait for redirect state
- terminate `nie`
- verify cleanup after exit

- [ ] **Step 7: Run the focused integration suite to verify GREEN**

Run:

```bash
go test -tags=integration ./test -run 'TestSmoke_(AuditModeAllowsUnknownTrafficButEmitsWouldDeny|EnforceBlocksUnknownTrafficUntilDNSLearning|EnforceKeepsActiveTCPFlowAcrossDNSRotationAndEventuallyPrunesStaleIP)$' -count=1
```

Expected: PASS.

- [ ] **Step 8: Commit the integration hardening**

Run:

```bash
git add test/smoke_test.go test/integration_probes_test.go
git commit -m "test: cover dns rotation trust cleanup"
```

### Task 4: Document Trust Tuning And Final Verification

**Files:**
- Modify: `README.md`
- Modify: `config.yaml`
- Test: repository verification commands

- [ ] **Step 1: Write the failing documentation expectation**

Before editing docs, note the missing items and treat them as the documentation delta to close:

- `config.yaml` does not show `trust:`
- `README.md` configuration section does not document `trust.max_stale_hold`
- `README.md` configuration section does not document `trust.sweep_interval`
- `README.md` DNS flow section does not state that cleanup cadence is operator-tunable

- [ ] **Step 2: Update the sample config**

Add:

```yaml
trust:
  max_stale_hold: 0s
  sweep_interval: 30s
```

to `config.yaml` in a sensible position near `dns:` / `policy:`.

- [ ] **Step 3: Update the README**

Document:

- the new top-level `trust:` block in the configuration example
- what each trust setting means
- that `max_stale_hold=0s` still does not override active TCP conntrack protection
- that cleanup cadence is tunable while the default remains conservative

- [ ] **Step 4: Run the full repository test suite**

Run: `go test ./... -count=1`

Expected: PASS.

- [ ] **Step 5: Run the integration smoke test for the new scenario**

Run: `go test -tags=integration ./test -run TestSmoke_EnforceKeepsActiveTCPFlowAcrossDNSRotationAndEventuallyPrunesStaleIP -count=1`

Expected: PASS.

- [ ] **Step 6: Inspect the final branch state**

Run:

```bash
git status --short
git log --oneline --decorate -n 5
```

Expected:

- only intended doc/code changes are present
- commits line up with the plan

- [ ] **Step 7: Commit the docs and verification-ready state**

Run:

```bash
git add README.md config.yaml
git commit -m "docs: describe trust cleanup tuning"
```
