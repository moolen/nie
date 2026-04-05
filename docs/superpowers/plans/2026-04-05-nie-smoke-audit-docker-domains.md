# Smoke Audit Docker Domains Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a root-gated integration smoke test that runs `nie` in `audit` mode on the default outbound interface during a pinned `spectre` `docker build`, then asserts the exact required audited domains for that pinned build.

**Architecture:** Keep the new behavior in the integration test harness instead of production code. Add small test-local helpers for default-route interface detection, pinned repo checkout, and audited-host extraction; cover the deterministic parsing logic with focused unit tests and use one root-gated smoke test for the real network and Docker path. Update CI smoke invocation to include the new test.

**Tech Stack:** Go, root-gated integration tests, Docker CLI/daemon, git CLI, existing `nie` smoke harness, GitHub Actions

---

### Task 1: Add Audited Domain Extraction Helpers And Unit Tests

**Files:**
- Modify: `test/smoke_test.go`
- Test: `test/smoke_test.go`

- [ ] **Step 1: Write the failing audited-domain extraction test**

Add a focused unit test in `test/smoke_test.go`, for example `TestExtractAuditedDomains`, using a synthetic multiline log input that includes:

```text
time=... level=INFO msg=would_deny_dns host=registry.npmjs.org.
time=... level=INFO msg=would_deny_dns host=proxy.golang.org.
time=... level=INFO msg=would_deny_https host=AUTH.DOCKER.IO
time=... level=INFO msg=would_deny_egress proto=tcp dst=203.0.113.10 port=443
time=... level=INFO msg=would_deny_https host=registry-1.docker.io
```

Assert that the returned set is exactly:

- `auth.docker.io`
- `proxy.golang.org`
- `registry-1.docker.io`
- `registry.npmjs.org`

and that:

- hostnames are lowercased
- trailing dots are stripped
- non-host audit lines are ignored
- duplicates are removed

- [ ] **Step 2: Run the focused helper test to verify RED**

Run: `go test ./test -run TestExtractAuditedDomains -count=1`

Expected: FAIL because the helper does not exist yet.

- [ ] **Step 3: Implement the audited-domain extraction helper**

In `test/smoke_test.go`, add a small helper such as:

```go
func extractAuditedDomains(logs string) map[string]struct{}
```

Implementation requirements:

- scan logs line-by-line
- only consider `would_deny_dns` and `would_deny_https` lines
- parse `host=...`
- normalize with lowercase + trim trailing `.`
- ignore empty values

Also add:

```go
func sortedDomainSet(set map[string]struct{}) []string
```

to make failure output stable.

- [ ] **Step 4: Run the focused test to verify GREEN**

Run: `go test ./test -run TestExtractAuditedDomains -count=1`

Expected: PASS.

- [ ] **Step 5: Commit the helper coverage**

Run:

```bash
git add test/smoke_test.go
git commit -m "test: add audited domain extraction helpers"
```

### Task 2: Add Default Outbound Interface And Pinned Spectre Checkout Helpers

**Files:**
- Modify: `test/smoke_test.go`
- Test: `test/smoke_test.go`

- [ ] **Step 1: Write failing tests for route and normalization helpers**

Add focused tests for any pure helper logic you introduce around command parsing, for example:

- `TestParseDefaultRouteInterface`
- `TestNormalizeAuditedDomain`

If route detection is shell-backed, keep only the parsing logic unit-tested and leave command execution integration-tested indirectly.

Example parser input:

```text
default via 192.0.2.1 dev eth0 proto dhcp src 192.0.2.10 metric 100
```

Assert the parsed interface is `eth0`.

- [ ] **Step 2: Run the focused parser tests to verify RED**

Run: `go test ./test -run 'Test(ParseDefaultRouteInterface|NormalizeAuditedDomain)' -count=1`

Expected: FAIL because the helper functions do not exist yet.

- [ ] **Step 3: Implement default-route interface detection**

In `test/smoke_test.go`, add helpers along the lines of:

```go
func defaultRouteInterface(t *testing.T) string
func parseDefaultRouteInterface(output string) (string, error)
```

Implementation guidance:

- use `ip route show default`
- parse the `dev <iface>` token
- fail with the command output included if parsing fails

- [ ] **Step 4: Implement pinned spectre checkout helper**

In `test/smoke_test.go`, add a helper such as:

```go
func checkoutPinnedSpectre(t *testing.T, dir string) string
```

Requirements:

- clone `https://github.com/moolen/spectre`
- check out pinned commit `e49f8e0899616842cff5441bc4d9ee10c0667f20`
- return the checkout path
- include command output in failures

Keep the pin in a named constant near the smoke test.

- [ ] **Step 5: Run the focused helper tests to verify GREEN**

Run: `go test ./test -run 'Test(ParseDefaultRouteInterface|NormalizeAuditedDomain|ExtractAuditedDomains)' -count=1`

Expected: PASS.

- [ ] **Step 6: Commit the route and checkout helpers**

Run:

```bash
git add test/smoke_test.go
git commit -m "test: add outbound route helpers for smoke"
```

### Task 3: Add Root-Gated Docker Build Audit Smoke Test

**Files:**
- Modify: `test/smoke_test.go`
- Test: `test/smoke_test.go`

- [ ] **Step 1: Write the failing integration smoke test**

Add a new test in `test/smoke_test.go`:

```go
func TestSmoke_AuditCapturesPinnedDockerBuildDomains(t *testing.T)
```

Test skeleton:

1. Skip unless `os.Geteuid() == 0`
2. Skip unless Docker is available and usable
3. Detect the default outbound interface
4. Start `nie` in `audit` mode using that interface
5. Clone pinned `spectre`
6. Run `docker build`
7. Stop `nie`
8. Extract audited domains from logs
9. Assert exact required domains are present

Required domain set:

- `auth.docker.io`
- `registry-1.docker.io`
- `registry.npmjs.org`
- `proxy.golang.org`
- `sum.golang.org`
- `dl-cdn.alpinelinux.org`

- [ ] **Step 2: Run the single smoke test to verify RED**

Run:

```bash
go test -tags=integration ./test -run TestSmoke_AuditCapturesPinnedDockerBuildDomains -count=1 -v
```

Expected: FAIL because the new smoke test and helpers are not complete yet.

- [ ] **Step 3: Implement Docker availability helper**

In `test/smoke_test.go`, add a helper such as:

```go
func requireDockerAvailable(t *testing.T)
```

Requirements:

- check `docker version` or `docker info`
- skip with a precise message if Docker is unavailable

- [ ] **Step 4: Implement the smoke test end-to-end**

Use the existing harness patterns:

- `repoRoot(t)`
- `resolveNieBinary(t, root, tmpDir)`
- `writeConfig(...)`
- `waitForPinnedState(...)`
- `waitForNieRedirectState(...)`
- `terminateNieProcess(...)`

Key implementation points:

- use the default outbound interface instead of `lo`
- keep mode `audit`
- still provide DNS/HTTPS listener addresses on loopback for config completeness
- bound the test with a generous context timeout, for example `5*time.Minute`
- run `docker build` in the checked-out `spectre` directory
- include build output in failure messages
- after process termination, compute:

```go
observed := extractAuditedDomains(logs.String())
```

- fail with a stable diff-like message listing missing and observed domains

- [ ] **Step 5: Run the single integration test to verify GREEN**

Run:

```bash
sudo -E go test -tags=integration ./test -run TestSmoke_AuditCapturesPinnedDockerBuildDomains -count=1 -v
```

Expected: PASS on a root-capable host with working Docker and outbound internet.

- [ ] **Step 6: Commit the new smoke test**

Run:

```bash
git add test/smoke_test.go
git commit -m "test: add docker audit smoke coverage"
```

### Task 4: Wire CI Smoke To Run The New Integration Test

**Files:**
- Modify: `.github/workflows/ci.yml`
- Test: `.github/workflows/ci.yml`

- [ ] **Step 1: Write the failing CI expectation implicitly via workflow target expansion**

Update the smoke workflow target in `.github/workflows/ci.yml` so the root smoke command includes:

- `TestSmoke_AuditModeAllowsUnknownTrafficButEmitsWouldDeny`
- `TestSmoke_AuditCapturesPinnedDockerBuildDomains`
- `TestSmoke_EnforceBlocksUnknownTrafficUntilDNSLearning`

Keep the existing explicit test-name filtering pattern.

- [ ] **Step 2: Run workflow validation to verify RED/GREEN once edited**

Run:

```bash
go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.8 .github/workflows/ci.yml
```

Expected: PASS after the edit; if it fails, fix workflow syntax before proceeding.

- [ ] **Step 3: Commit the CI wiring**

Run:

```bash
git add .github/workflows/ci.yml
git commit -m "ci: run docker audit smoke test"
```

### Task 5: Final Verification

**Files:**
- Verify: `test/smoke_test.go`
- Verify: `.github/workflows/ci.yml`

- [ ] **Step 1: Run the focused non-root test coverage**

Run:

```bash
go test ./test -run 'Test(ParseDefaultRouteInterface|NormalizeAuditedDomain|ExtractAuditedDomains)' -count=1
```

Expected: PASS.

- [ ] **Step 2: Run the full repository test suite**

Run:

```bash
go test ./... -count=1
```

Expected: PASS.

- [ ] **Step 3: Run the targeted root-gated smoke command**

Run:

```bash
sudo -E go test -tags=integration ./test -run 'TestSmoke_(AuditModeAllowsUnknownTrafficButEmitsWouldDeny|AuditCapturesPinnedDockerBuildDomains|EnforceBlocksUnknownTrafficUntilDNSLearning)' -count=1 -v
```

Expected: PASS on a root-capable Docker-enabled host.

- [ ] **Step 4: Validate GitHub Actions workflow syntax**

Run:

```bash
go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.8 .github/workflows/ci.yml
```

Expected: PASS.

- [ ] **Step 5: Request code review before merge**

Review the full diff with a code-review mindset, focusing on:

- brittle domain assumptions
- interface-detection fragility
- accidental dependence on loopback-specific behavior
- test flakiness from Docker/network timing

- [ ] **Step 6: Commit any review-driven follow-ups**

Run:

```bash
git add <changed files>
git commit -m "fix: harden docker audit smoke assertions"
```

only if review follow-up changes are needed.
