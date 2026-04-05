# nie Architecture Reshape Design

## Goal

Reshape the codebase so the runtime architecture and data flow are explicit,
testable, and easier to evolve without changing behavior.

The main target is the current composition root in `cmd/nie/main.go`, which
currently mixes:

- CLI concerns
- config loading
- interface preflight validation
- policy construction
- DNS upstream wiring
- HTTPS MITM wiring
- redirect and eBPF construction
- lifecycle orchestration
- audit event logging

The intent of this reshape is to make the system easier to reason about, not to
change the core security model or product scope.

## Current Problems

### 1. `cmd/nie/main.go` owns too much

The entrypoint currently contains both application assembly and runtime logic.
That makes the main datapath difficult to read because control flow and
dependency wiring are interleaved.

### 2. Data flow is present but not centered

The actual flow is good:

1. config
2. interface preflight
3. policy/trust-plan construction
4. eBPF/redirect startup
5. DNS interception and trust learning
6. HTTPS interception and policy enforcement
7. audit event logging

But that flow is not represented by a dedicated application-level package. It is
instead reconstructed inline inside `main.go`.

### 3. Adapters live in the wrong layer

The DNS listener adapter and DNS upstream dialer are runtime/application
adapters, but they currently live in the CLI file. That makes package
boundaries harder to understand.

### 4. Test seams are tied to the CLI package

The current builder indirection is useful, but it is shaped around `cmd/nie`
instead of around an application package. As a result, architecture tests and
runtime-wiring tests are anchored to the executable package.

## Design

### Recommended Shape

Introduce a dedicated application wiring package:

- `internal/app`

`internal/app` becomes the sole composition root for the daemon runtime.

`cmd/nie` becomes CLI-only and is reduced to:

- parse flags
- read config file
- create logger/context
- call `app.Run(...)`

### Package Responsibilities

#### `cmd/nie`

Keep only process entry responsibilities:

- argument parsing
- config file IO
- process exit codes
- signal context creation

It should not know how DNS, MITM, eBPF, redirect, or audit logging are wired.

#### `internal/app`

Own application assembly and orchestration:

- preflight interface validation
- policy and trust-plan construction
- marked dialer construction
- DNS upstream construction
- HTTPS CA/proxy/service construction
- redirect manager construction
- eBPF manager construction
- runtime lifecycle composition
- audit egress logger lifecycle

This package is where the system-level data flow should be readable from top to
bottom.

Important boundary:

- `internal/app` owns **construction and coordination**
- `internal/runtime` owns **ordered start/stop execution**

In other words, `internal/app` decides which lifecycle participants exist and
hands them to `internal/runtime`; `internal/runtime` executes the lifecycle
contract and rollback behavior.

#### `internal/runtime`

Keep it small and focused as a lifecycle sequencer:

- start ordered components
- rollback on startup failure
- stop in reverse order

It should remain ignorant of config parsing, dependency assembly, and policy
construction details.

This reshape does **not** require generalizing `internal/runtime` into a fully
generic graph executor. Keeping the current explicit lifecycle slots is fine for
this codebase size as long as the package stays responsible only for ordered
start/stop semantics rather than application wiring.

#### `internal/dnsproxy`

Continue to own DNS decision logic and trust learning.

Do not move listener/network-serving concerns into this package during this
reshape. Keep `internal/dnsproxy` focused on DNS request handling, upstream
exchange, and trust learning only.

The DNS network-serving adapter currently in `cmd/nie` should move into an
app-scoped adapter file instead: `internal/app/dns.go`.

#### `internal/mitm`

Keep ownership of:

- TLS client-hello classification
- transparent HTTPS service
- decrypted HTTP policy enforcement
- CA and leaf issuance

Do not move MITM internals into the app layer; only move wiring.

### Wiring Rule

`internal/app` may:

- translate config into constructor arguments
- create concrete adapters
- connect package outputs to package inputs

`internal/app` must **not** absorb domain logic from `internal/dnsproxy`,
`internal/mitm`, `internal/policy`, `internal/httppolicy`, `internal/redirect`,
or `internal/ebpf`.

Examples:

- allowed in `internal/app`: build a marked dialer and pass it into a DNS
  upstream adapter
- allowed in `internal/app`: load the MITM CA and construct `mitm.NewProxy(...)`
- not allowed in `internal/app`: reimplement DNS hostname decision logic
- not allowed in `internal/app`: reimplement HTTP request policy evaluation
- not allowed in `internal/app`: reimplement trust-entry learning semantics

#### `internal/redirect`, `internal/ebpf`, `internal/policy`, `internal/httppolicy`

Keep these as focused domain/infrastructure components with narrow APIs.

## Proposed File Structure

### New `internal/app` package

Suggested files:

- `internal/app/run.go`
  - `Run(ctx, cfg, logger) error`
  - startup/shutdown orchestration
- `internal/app/build.go`
  - component assembly
  - runtime service construction
- `internal/app/preflight.go`
  - protected interface validation
- `internal/app/audit.go`
  - audit event logger lifecycle
- `internal/app/dns.go`
  - DNS listener lifecycle adapter
  - DNS upstream adapter

This keeps network adapter code in the composition layer while preserving
`internal/dnsproxy` as a focused handler package.

### Simplified `cmd/nie`

Suggested files:

- `cmd/nie/main.go`
  - CLI/process shell only

## Data Flow After Reshape

The intended top-level flow inside `internal/app`:

1. validate protected interface
2. build hostname policy from config
3. build DNS trust plan from config
4. build HTTP MITM policy from config
5. construct marked dialer
6. construct eBPF manager
7. construct redirect manager
8. construct HTTPS CA/cache/proxy/service
9. construct DNS upstream/server/listener lifecycle
10. assemble runtime lifecycle group
11. start lifecycle group
12. start audit logger when in audit mode
13. wait for cancellation
14. stop audit logger
15. stop lifecycle group

This makes the system’s architecture legible in one place.

### Required Runtime Start/Stop Order

The runtime lifecycle order must remain explicit and unchanged unless a later
design intentionally revisits datapath ordering:

- start: `EBPF -> DNS -> HTTPS -> Redirect`
- stop: `Redirect -> HTTPS -> DNS -> EBPF`

Why this remains the contract:

- eBPF first so the enforcement plane is prepared before network redirection is
  installed
- DNS and HTTPS listeners before redirect so traffic is not redirected into an
  unbound local port
- redirect last so interception activates only after local consumers are ready
- reverse stop order so new interception is removed before the local listeners
  and eBPF state are torn down

This order should remain owned by `internal/runtime`, while the decision to
populate those lifecycle slots remains owned by `internal/app`.

## Testing Strategy

### Preserve Existing Behavior

The reshape is behavioral-preserving. Existing package tests should continue to
pass.

Behavior-preservation specifically includes:

- identical runtime start order
- identical runtime stop order
- identical rollback behavior on startup failure
- identical audit logger startup/stop semantics
- identical config-to-component translation

### Move Assembly Tests

Current wiring tests in `cmd/nie/main_test.go` should move to `internal/app`
tests because they validate runtime assembly, not CLI behavior.

Those tests should remain package-internal tests for `internal/app`, so the
reshape does not require exporting application internals just to preserve test
coverage.

CLI tests should only cover:

- missing flag handling
- config read/load failure handling
- `app.Run` result propagation

### Add Focused Application Tests

Add tests around:

- runtime build success path
- interface validation failure
- constructor failure wrapping
- audit logger startup/shutdown behavior
- live trust writer delegation
- rollback behavior on startup failures
- stop-timeout context propagation
- audit logger startup failure causing lifecycle rollback
- runtime lifecycle order equivalence versus the pre-reshape contract

### End-to-End Verification

After the refactor, at least one privileged validation path should still be run
unchanged to prove the reshape did not alter behavior:

- the existing smoke/integration path, or
- the VM-backed e2e path

The purpose is not to add new coverage, but to prove the extracted composition
root preserves the deployed runtime behavior.

## Migration Strategy

Implement the reshape incrementally inside one branch, but in this order:

1. introduce `internal/app` with thin wrappers around existing `cmd/nie`
   assembly helpers
2. move preflight validation and audit logger helpers into `internal/app`
3. move DNS listener/upstream adapters into `internal/app/dns.go`
4. move runtime assembly helpers into `internal/app/build.go`
5. reduce `cmd/nie/main.go` to CLI/process-shell concerns only
6. move assembly-focused tests from `cmd/nie` to `internal/app`
7. re-run package tests and one privileged validation path

This order minimizes churn because it preserves behavior while shrinking
`cmd/nie` step by step instead of forcing a package move and API redesign at the
same time.

## Non-Goals

- changing the egress enforcement model
- redesigning policy formats
- introducing IPv6 support
- changing nftables/eBPF semantics
- broad hexagonal abstraction for every package

## Recommendation

Proceed with the `internal/app` composition-root extraction in one refactor
pass, while keeping the lower-level packages stable. This yields clearer
architecture and data flow without excessive churn or speculative abstraction.
