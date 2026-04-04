# nie VM E2E Extension Design

## Summary

Extend the Vagrant-based VM validation so it proves real non-loopback egress
enforcement on the guest's primary interface, then broaden the same harness with
additional DNS and policy cases.

The first phase is about the datapath. It must show that `nie` blocks direct
egress by default, then allows the same destination after an allowed DNS answer
teaches the IPv4 into the eBPF allow map. The second phase reuses that harness to
cover more DNS and policy behavior in both `enforce` and `audit`.

## Goals

- Prove `nie` enforces real egress policy on a VM interface other than `lo`.
- Keep the VM end-to-end test deterministic and self-contained.
- Reuse the existing Vagrant workflow instead of creating a separate test lab.
- Add broader policy-path coverage once the primary datapath proof exists.

## Non-Goals

- multi-VM orchestration
- internet-dependent reachability tests
- libvirt or additional provider support
- namespace or multi-interface production support in `nie`
- replacing the existing root-gated host integration tests

## Recommended Approach

Use a host-assisted fixture over a stable Vagrant private network.

The host runs a simple TCP or HTTP fixture server bound to the Vagrant private
network address. The guest gets a predictable private-network IP on its primary
test path. A VM-only integration test then:

1. starts `nie` in `enforce`
2. attempts direct egress from the guest to the fixture IP and confirms it is
   blocked
3. resolves an allowed hostname through `nie` to that same fixture IP
4. retries the same egress and confirms it now succeeds

That keeps the test deterministic and avoids relying on external DNS or public
network behavior.

## Alternatives Considered

### Public Internet Targets

Rejected for the primary test path. Failures would be ambiguous because they could
come from upstream reachability, NAT, firewalling, or the test target itself.

### In-Guest Synthetic Network Lab

Possible with extra interfaces or veth pairs, but too much machinery for the first
extension. It adds setup complexity without improving confidence enough over a
stable private-network host fixture.

## Phase 1: Real Datapath E2E

### Network Topology

- Keep the existing Vagrant guest.
- Add one stable private-network address for the guest.
- Use the host as the fixture endpoint on the same private network.

The private network provides a deterministic non-loopback path that is still local
to the development machine.

### Host Fixture

Add a small host-side test helper that:

- binds a stable address on the Vagrant private network
- listens on one TCP port
- responds with a minimal success payload
- stays alive only for the duration of the VM test run

The host fixture should be simple enough to inspect manually if a failure occurs.

### Guest Test Flow

The VM-only integration test should:

1. discover the guest's non-loopback interface used for the private network
2. write a `nie` config in `enforce` mode for that interface
3. start a fake upstream DNS server in the guest that answers an allowed hostname
   with the host fixture IP
4. start `nie`
5. verify direct TCP egress to the fixture IP fails before DNS learning
6. send an allowed DNS query through `nie`
7. verify TCP egress to the same fixture IP succeeds after learning
8. stop `nie`
9. verify cleanup of redirect and pinned state

This test proves both default-deny and learned-allow behavior on a real egress
path rather than the current loopback-safe smoke path.

### Why A Host Fixture Works

- the guest path is real non-loopback egress
- the target address is deterministic
- the setup avoids external network dependencies
- the existing Vagrant harness already gives us a repeatable place to run it

## Phase 2: Broader DNS And Policy Cases

Once phase 1 is stable, extend the VM harness with additional cases that reuse the
same helper structure:

- `enforce`: denied hostname gets `REFUSED`
- `enforce`: allowed hostname resolves and unblocks matching egress
- `audit`: denied hostname still resolves and logs `would_deny_dns`
- `audit`: unknown egress is allowed and logs `would_deny_egress`
- shutdown still removes nftables and bpffs state

These tests should be incremental additions, not a second independent harness.

## Runtime Architecture

### Host Side

#### VM Runner

The Vagrant runner becomes responsible for:

- preparing environment variables for VM-only tests
- starting the host fixture before guest-side tests
- stopping the fixture after the run

It should continue to run the mounted repository directly inside the VM.

#### Fixture Helper

The fixture helper can be a tiny shell or Go program, but it should be minimal and
stable. Its only job is to provide one reachable non-loopback TCP service for the
guest.

### Guest Side

#### VM-Only Integration Test

Add a new integration test file or extend the current smoke suite with VM-gated
cases driven by environment variables such as:

- guest test interface name
- host fixture IP and port
- a flag enabling VM-only coverage

The test must skip cleanly when those VM-only inputs are absent so the regular host
integration workflow still works.

## Data Flow

1. The developer runs the Vagrant VM test command.
2. The host runner starts the fixture on the Vagrant private network.
3. The guest test process receives fixture and interface settings.
4. The guest starts `nie` on the chosen interface.
5. The guest attempts direct egress to the fixture and sees default deny.
6. The guest resolves an allowed hostname through `nie`.
7. `nie` learns the returned IPv4 into the allow map.
8. The guest retries egress and reaches the fixture successfully.
9. Additional DNS/policy cases run on the same harness.
10. The runner stops the fixture and leaves the VM available for inspection.

## Error Handling

- If the host fixture cannot bind the expected address or port, fail before guest
  tests start.
- If the guest cannot identify the configured interface, fail with a clear message.
- VM-only tests should skip, not fail, when their required environment is missing
  outside the Vagrant workflow.
- Failures must leave the VM running for inspection.

## File Plan

- Modify: `vm/vagrant/Vagrantfile`
- Modify: `vm/vagrant/run-tests.sh`
- Modify: `Makefile` if the host fixture lifecycle needs host-side orchestration
- Modify or create: `test/` integration test files for VM-only cases
- Modify: `README.md` to document the stronger VM e2e coverage and any new workflow

## Acceptance Criteria

- The VM workflow proves direct non-loopback egress is denied before DNS learning.
- The VM workflow proves the same destination is allowed after an allowed hostname
  resolves to that IP.
- The VM-only tests remain deterministic and do not depend on public internet
  reachability.
- Existing host integration tests still run without the VM-only environment.
- The broader DNS and policy cases can be layered on the same harness after the
  datapath proof is working.
