# nie Optional HTTPS Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the `https:` config block optional, disable MITM interception when it is omitted, and preserve DNS-based hostname enforcement by falling back to standard TLS trust ports.

**Architecture:** Track whether HTTPS was configured at config-load time, then branch in app wiring. DNS, eBPF, and redirect lifecycles continue to run, but HTTPS proxy/service and HTTPS redirect rules are only built when HTTPS is enabled.

**Tech Stack:** Go 1.24, `testing`, existing `internal/config`, `internal/app`, `internal/redirect`

---

### Task 1: Lock in optional-HTTPS behavior with tests

**Files:**
- Modify: `internal/config/config_test.go`
- Modify: `internal/app/app_test.go`
- Modify: `internal/redirect/manager_test.go`

- [ ] **Step 1: Write failing config tests**

Cover:
- omitted `https:` loads successfully
- HTTPS enabled defaults still apply when the block is present

- [ ] **Step 2: Write failing redirect tests**

Cover:
- redirect manager accepts DNS-only config and installs only DNS redirects

- [ ] **Step 3: Write failing app tests**

Cover:
- HTTPS lifecycle is nil when HTTPS is disabled
- DNS trust plan still returns fallback ports `443` and `8443`

- [ ] **Step 4: Run targeted tests to verify red**

Run: `go test ./internal/config ./internal/redirect ./internal/app`
Expected: FAIL because HTTPS is currently mandatory

### Task 2: Implement optional config and runtime wiring

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/app/build.go`
- Modify: `internal/redirect/manager.go`

- [ ] **Step 1: Track HTTPS presence in config loading**

Add an internal presence bit on `config.HTTPS` and gate validation/defaulting on
that bit.

- [ ] **Step 2: Allow DNS-only redirect manager configs**

Relax redirect manager validation so empty HTTPS redirect sets are valid.

- [ ] **Step 3: Skip HTTPS runtime construction when disabled**

Only build CA, MITM policy, proxy, and HTTPS service when HTTPS is enabled.
Keep DNS trust ports on fallback standard TLS ports when HTTPS is disabled.

- [ ] **Step 4: Re-run targeted tests**

Run: `go test ./internal/config ./internal/redirect ./internal/app`
Expected: PASS

### Task 3: Update docs and verify the repo

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Document optional HTTPS behavior**

Explain that omitting `https:` disables interception and MITM, while hostname
policy still applies to standard TLS destinations.

- [ ] **Step 2: Run full verification**

Run: `go test ./...`
Expected: PASS
