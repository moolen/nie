# nie Security Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the reviewed HTTPS/SNI, MITM lifecycle, and IPv6 fail-closed security gaps.

**Architecture:** Keep the existing IPv4-only datapath. Harden request validation inside the MITM proxy, harden connection lifecycle inside the MITM service, and add host-interface validation before runtime construction.

**Tech Stack:** Go, stdlib `net`, `net/http`, `crypto/tls`, existing MITM/runtime tests

---

### Task 1: Add Failing MITM Authority Regression Tests

**Files:**
- Modify: `internal/mitm/proxy_test.go`

- [ ] Step 1: Write failing tests for HTTP/1 and HTTP/2 authority mismatch behavior.
- [ ] Step 2: Run the targeted MITM tests and verify they fail for the current implementation.
- [ ] Step 3: Implement the minimal proxy-side authority validation.
- [ ] Step 4: Re-run the targeted MITM tests and verify they pass.

### Task 2: Add Failing MITM Service Lifecycle Tests

**Files:**
- Modify: `internal/mitm/service_test.go`
- Modify: `internal/mitm/service.go`

- [ ] Step 1: Write failing tests for stop-with-stalled-connection and client-hello timeout.
- [ ] Step 2: Run the targeted service tests and verify they fail or hang without the fix.
- [ ] Step 3: Implement connection tracking, stop-time close, and client-hello timeout handling.
- [ ] Step 4: Re-run the targeted service tests and verify they pass.

### Task 3: Add Failing IPv6 Fail-Closed Startup Test

**Files:**
- Modify: `cmd/nie/main_test.go`
- Modify: `cmd/nie/main.go`

- [ ] Step 1: Write a failing runtime-build test for protected-interface IPv6 validation.
- [ ] Step 2: Run the targeted `cmd/nie` tests and verify they fail.
- [ ] Step 3: Implement interface validation with an injectable builder dependency.
- [ ] Step 4: Re-run the targeted `cmd/nie` tests and verify they pass.

### Task 4: Broader Verification and Documentation

**Files:**
- Modify: `README.md`

- [ ] Step 1: Update the README to document Host/SNI strictness and IPv6 fail-closed startup.
- [ ] Step 2: Run focused packages: `go test ./internal/mitm ./cmd/nie -count=1`.
- [ ] Step 3: Run broader related verification: `go test ./internal/... ./cmd/nie -count=1`.
- [ ] Step 4: Review the diff for scope and keep only the hardening changes.
