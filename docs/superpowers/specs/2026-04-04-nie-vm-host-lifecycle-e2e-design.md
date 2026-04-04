# nie VM Host Lifecycle E2E Design

## Summary

Validate the real use case where `nie` is started on a host, an already-running
untrusted process loses host-wide network access while `nie` enforces policy,
that same process regains normal networking after `nie` shuts down, and the full
start-stop cycle can be repeated without leaving stale redirect or eBPF state.

This extends the existing Vagrant VM workflow rather than introducing a separate
test harness. The VM remains the validation environment because the behavior is
rootful and host-wide, and the existing suite already proves the core datapath
and cleanup model there.

## Goals

- Prove `nie` can be started and stopped repeatedly on a host without leaving the
  host networking stack stuck in an enforced state.
- Prove a single long-lived process on the guest experiences network loss and
  recovery as host-wide `nie` policy is enabled and removed.
- Reuse the existing deterministic host-side fixture and fake upstream DNS setup.
- Turn this lifecycle into a repeatable VM integration test.

## Non-Goals

- Per-process traffic scoping or isolation
- Namespace-based isolation
- Multi-host or clustered behavior
- TLS interception or MITM behavior
- Replacing the existing VM datapath and audit-policy coverage

## Current Constraints

- `nie` remains host-wide in v1. When it runs in `enforce`, unknown egress is
  dropped for the host path on the configured interface.
- The test target is a single running process, but the enforcement semantics stay
  host-wide.
- The existing VM harness already provides:
  - a deterministic host-side TCP fixture on the Vagrant private network
  - a fake upstream DNS server in the guest
  - helpers for starting and stopping `nie`
  - cleanup assertions for nftables and bpffs state

## Recommended Approach

Add one small long-lived helper process to the VM integration suite.

The helper process starts once and stays alive across the entire test. It
repeatedly attempts:

1. direct TCP to the fixture IP and port
2. DNS resolution for an allowed hostname through the local DNS listener
3. TCP to the same destination after DNS learning is expected

The helper emits structured phase observations to stdout so the test can assert
state transitions without relying on shell parsing or guest package tools.

The main VM test controls `nie` start and stop around that helper and checks that
the helper transitions through:

- baseline connectivity before `nie`
- host-wide block behavior while `nie` is active and the destination is untrusted
- recovery after `nie` stops
- repeated block and recovery on a second start-stop cycle

## Why A Dedicated Helper Is Preferred

### Long-Lived Helper Process

Recommended.

- Matches the user’s real use case
- Proves the same running process loses and regains connectivity
- Keeps assertions deterministic because probe behavior is under our control
- Avoids dependence on `curl`, `dig`, `nc`, or distro packaging differences

### Shell Loop With Guest Tools

Rejected.

- More fragile output parsing
- More variation across guest images
- Harder to attribute failure modes cleanly

### Repeated One-Shot Processes

Rejected for this use case.

- Does not prove that one already-running process survives `nie` teardown and
  regains access

## Test Flow

### Network Topology

Keep the current topology:

- guest reaches the host-side fixture over the Vagrant private network
- guest DNS queries go through `nie`
- the fake upstream DNS server returns the host fixture IPv4

### Lifecycle Sequence

The new VM lifecycle test should run this sequence:

1. Start the long-lived helper process before `nie`.
2. Assert baseline behavior:
   - direct TCP to the fixture succeeds
   - direct DNS to the upstream path works
3. Start `nie` in `enforce` mode on the routed non-loopback interface.
4. Assert the helper reports host-wide restriction:
   - unknown direct TCP fails
   - DNS through `nie` for denied names is refused
5. Trigger an allowed DNS lookup through `nie`.
6. Assert the helper reports restored access to the learned destination.
7. Stop `nie`.
8. Assert the same running helper process reports full recovery:
   - DNS works again without `nie`
   - direct TCP works again without `nie`
9. Start `nie` again.
10. Re-run the restriction and learning assertions.
11. Stop `nie` again.
12. Assert recovery again and verify cleanup of nftables and bpffs state.

This proves the operational property that starting and stopping `nie` is
reversible and repeatable for a long-lived host process.

## Helper Process Design

### Responsibilities

The helper should:

- start once and keep running until told to exit
- repeatedly probe configured endpoints on a short interval
- expose enough structured output for the test to wait for specific states

### Inputs

Environment variables or arguments should provide:

- fixture address
- allowed hostname
- DNS listener address to query when `nie` is running
- baseline upstream DNS address or raw fixture IP checks as needed
- probe interval and timeout

### Output Format

Use one line per observation in a machine-friendly format. JSON is acceptable,
but key-value log lines are also sufficient if they are stable. Each observation
should include:

- probe kind (`dns`, `tcp`)
- target
- result (`success`, `refused`, `timeout`, `error`)
- current cycle or phase marker if helpful

The test must be able to wait for “sustained” states rather than one lucky probe.

## VM Test Design

### New Coverage

Add one integration test focused on lifecycle repetition, for example:

- `TestVMLongLivedProcessRecoversAcrossNieRestart`

This test should reuse the current `startVMNieScenario`-style setup where useful,
but it likely needs a slightly more general harness because it must start and stop
`nie` multiple times within one test.

### Harness Changes

Refactor the current VM helpers so the test can:

- build the config once
- start `nie`
- stop `nie`
- restart `nie` with the same config
- reuse the same fixture and helper process across cycles

The helper process lifecycle should be independent from the `nie` lifecycle.

### Assertions

For each cycle, assert:

- before `nie`: connectivity available
- after `nie` starts: untrusted direct TCP blocked
- after allowed DNS learning: allowed destination reachable
- after `nie` stops: direct TCP and DNS recover

Also keep the existing shutdown cleanup assertions after each stop:

- `/sys/fs/bpf/nie` removed
- `nie` nftables redirect table/chain removed

## Error Handling

- If the helper exits early, fail immediately and surface its logs.
- If `nie` start or stop fails during either cycle, fail and include logs.
- If cleanup does not complete after stop, fail with explicit state details.
- If recovery does not happen within timeout after stop, treat that as the main
  regression this test is supposed to catch.

## File Plan

- Add: `test/<helper or support path>` for the long-lived probe process
- Modify: `test/vm_e2e_test.go`
- Possibly modify: `test/smoke_test.go` if shared helpers should move there
- Possibly modify: `vm/vagrant/run-tests.sh` only if the helper needs explicit
  build or environment wiring beyond normal `go test`
- Modify: `README.md` after implementation if the lifecycle coverage becomes part
  of the documented VM guarantees

## Acceptance Criteria

- A long-lived guest process loses host-wide untrusted egress when `nie` starts.
- The same running process regains DNS and direct TCP connectivity after `nie`
  stops.
- The start-stop behavior is repeatable in a second cycle in the same test.
- Cleanup still removes nftables redirect state and pinned bpffs state after each
  stop.
- The VM test remains deterministic and uses the existing private-network fixture.
