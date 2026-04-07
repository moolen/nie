# nie CIDR Allow Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a narrow `policy.cidr_allow` list of IPv4 CIDRs or single IPv4 addresses plus protocol, and enforce those rules through a pinned eBPF CIDR map so those destinations always pass NIE's L3/L4 policy.

**Architecture:** Extend config validation and normalization for static CIDR allow rules, add a pinned IPv4 LPM-trie CIDR map plus protocol mask in the tc/eBPF datapath, then add an app lifecycle that writes configured CIDR rules into that map during startup. Keep the existing allow-map for DNS-learned exact trust entries.

**Tech Stack:** Go 1.24, `testing`, existing `internal/config`, `internal/app`, `internal/ebpf`

---

### Task 1: Lock in config behavior with tests

**Files:**
- Modify: `internal/config/config_test.go`
- Modify: `internal/config/config.go`

- [ ] **Step 1: Write failing config tests**

Cover:
- valid `policy.cidr_allow` rules load successfully
- plain IPv4 addresses normalize to `/32`
- invalid CIDRs fail
- IPv6 rules fail
- invalid protocols fail
- duplicate normalized rules fail

- [ ] **Step 2: Run targeted config tests to verify red**

Run: `go test ./internal/config`
Expected: FAIL because `policy.cidr_allow` is not implemented yet

- [ ] **Step 3: Write minimal config implementation**

Add:
- `config.PolicyCIDRAllowRule`
- `Policy.CIDRAllow`
- normalization and validation helpers

- [ ] **Step 4: Re-run config tests**

Run: `go test ./internal/config`
Expected: PASS

### Task 2: Lock in eBPF CIDR writer behavior with tests

**Files:**
- Modify: `internal/ebpf/loader_test.go`
- Modify: `internal/ebpf/loader.go`
- Modify: `bpf/include/common.h`
- Modify: `bpf/egress.c`
- Regenerate: `internal/ebpf`

- [ ] **Step 1: Write failing eBPF writer tests**

Cover:
- normalized prefixes write to the CIDR map
- stored protocol masks match the configured protocol

- [ ] **Step 2: Run targeted eBPF tests to verify red**

Run: `go test ./internal/ebpf`
Expected: FAIL because the CIDR map and writer do not exist yet

- [ ] **Step 3: Write minimal kernel/userspace implementation**

Add:
- pinned CIDR LPM trie map
- protocol-mask value encoding
- tc lookup before the existing allow-map path
- Go-side CIDR writer and loader plumbing

- [ ] **Step 4: Re-run eBPF tests**

Run: `go test ./internal/ebpf`
Expected: PASS

### Task 3: Lock in app startup behavior with tests

**Files:**
- Modify: `internal/app/app_test.go`
- Modify: `internal/app/build.go`
- Modify: `internal/runtime/service.go`
- Modify: `internal/runtime/service_test.go`

- [ ] **Step 1: Write failing app tests**

Cover:
- startup preloads CIDR rules into the eBPF CIDR writer
- startup fails closed when CIDR preload fails
- runtime startup order places the CIDR preload after eBPF and before DNS

- [ ] **Step 2: Run targeted app tests to verify red**

Run: `go test ./internal/app ./internal/runtime`
Expected: FAIL because the static CIDR lifecycle does not exist yet

- [ ] **Step 3: Write minimal runtime implementation**

Add:
- config-to-eBPF CIDR rule conversion
- static preload lifecycle
- wiring into `runtime.Service` startup order

- [ ] **Step 4: Re-run app tests**

Run: `go test ./internal/app ./internal/runtime`
Expected: PASS

### Task 4: Align docs and examples

**Files:**
- Modify: `README.md`
- Modify: `config.yaml`

- [ ] **Step 1: Update docs to the narrow first-pass schema**

Document:
- `cidr` + `protocol` only
- plain-IP `/32` normalization
- longest-prefix-match eBPF enforcement
- lack of port or ICMP sub-rules in this first pass

- [ ] **Step 2: Re-run the touched-package tests**

Run: `go test ./internal/config ./internal/ebpf ./internal/app ./internal/runtime`
Expected: PASS

### Task 5: Verify the repo

**Files:**
- Modify: none

- [ ] **Step 1: Run broader verification**

Run: `go test ./...`
Expected: PASS
