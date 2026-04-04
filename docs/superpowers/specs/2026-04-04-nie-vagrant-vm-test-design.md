# nie Vagrant VM Test Harness Design

## Summary

Add a repo-local Vagrant harness that boots a single Ubuntu VM with the `virtualbox`
provider, mounts the current repository into the guest, provisions the guest with
the dependencies needed for `nie`, and runs the existing build and integration test
paths inside the VM.

The goal is not to create a generic lab environment. The goal is to make `nie`
testable in a clean guest that exercises the real privileged startup path, while
keeping the workflow simple enough to run from the repository with one command.

## Goals

- Provide a repeatable VM-based validation path for `nie`.
- Test the current working tree inside a clean Linux guest instead of only on the
  host.
- Reuse the existing `make` and `go test` entry points where possible.
- Keep the first version limited to one guest OS and one Vagrant provider.

## Non-Goals

- multi-VM orchestration
- multi-provider support in v1
- automatic VM destruction after successful runs
- a generic network lab with multiple guest interfaces
- replacing the existing host integration test workflow

## Recommended Approach

Create a `vm/vagrant` directory with:

- a `Vagrantfile` targeting Ubuntu on `virtualbox`
- a provision script that installs build and runtime dependencies required by the
  repo and the root-gated integration tests
- a guest runner script that executes the repo-local validation commands from the
  mounted workspace

Add a host `make vm-test` target that boots or reprovisions the VM and runs the
guest runner. The VM remains available after the run so debugging is possible with
`vagrant ssh`.

## VM Architecture

### Host Side

#### `vm/vagrant/Vagrantfile`

Defines a single Ubuntu guest, synced-folder mounts the repository, configures a
predictable working directory inside the guest, and sets `virtualbox` as the
default provider target for the documented workflow.

Responsibilities:

- choose a stable base image
- expose the mounted repo path to provisioners and test scripts
- register provisioning steps
- keep the configuration minimal and deterministic

#### `Makefile`

Adds a `vm-test` entry point that:

1. boots or reprovisions the guest
2. executes the guest runner inside the VM

This keeps the VM workflow aligned with the repo's existing `make` interface.

### Guest Side

#### Provisioning Script

Installs the minimum dependencies required to build and run `nie` in the guest.

Expected dependencies:

- Go toolchain
- clang/llvm toolchain needed by `go generate ./internal/ebpf`
- kernel headers and build helpers required by the generated eBPF path
- nftables, iproute2, and related networking utilities used by the runtime tests
- `make` and any small shell tooling the repo already assumes

Provisioning should be idempotent. Re-running `vagrant provision` must be safe.

#### Guest Test Runner

Runs from the mounted repository and executes the validation sequence in this order:

1. `make generate`
2. `go test ./...`
3. `go test -tags=integration ./test/... -v`

The runner executes as root where needed so the integration test can manage bpffs,
nftables, and tc state inside the guest.

## Test Strategy

### Reused Coverage

The first VM pass should reuse the current suite instead of inventing a parallel
test stack:

- unit tests validate config, policy, DNS proxy, redirect, runtime, and eBPF helper
  behavior
- the existing integration smoke test validates real privileged startup, audit-mode
  DNS handling, pinned-state creation, nftables redirect setup, and teardown cleanup

### VM-Specific Value

Running the existing suite inside a fresh guest adds confidence that:

- `nie` does not depend on accidental host-local state
- bpffs mount/setup works in a new system
- nftables and tc lifecycle logic work in a clean VM network stack
- repo setup instructions are complete enough to bootstrap a new machine

### Future Extension

If the first VM harness is stable, a follow-up can add a stricter guest-only
datapath test that verifies non-loopback enforcement on the guest primary
interface. That is intentionally deferred to keep the initial harness focused.

## Data Flow

1. The developer runs `make vm-test` from the repo root.
2. Vagrant boots the Ubuntu guest or reprovisions an existing one.
3. The repository is mounted into the guest.
4. The provision script installs or refreshes dependencies.
5. The guest runner enters the mounted repository path.
6. The runner executes the generate, unit-test, and integration-test commands.
7. Results are streamed back through `vagrant ssh -c ...` to the host terminal.
8. The VM remains available for inspection until the developer explicitly destroys
   it.

## Operational Constraints

- The initial harness targets one host interface model only; no extra NIC setup is
  required.
- The guest workflow assumes root is available via `sudo` or direct root execution
  for privileged tests.
- The mounted repository must remain the source of truth; the harness should not
  copy a second working tree into the guest.
- The harness must not mutate tracked repo files during provisioning beyond normal
  build/test artifacts already produced by the repo commands.

## Failure Handling

- Provisioning failures should stop the VM workflow immediately with a clear
  command failure.
- Test failures should leave the VM running so logs and live state can be
  inspected.
- The host-facing workflow should document explicit cleanup with
  `vagrant destroy -f`.

## User Workflow

Primary commands:

- `make vm-test` to boot/provision and run the VM validation sequence
- `cd vm/vagrant && vagrant ssh` to inspect the guest after a failure
- `cd vm/vagrant && vagrant destroy -f` to remove the VM

## File Plan

- Create: `vm/vagrant/Vagrantfile`
- Create: `vm/vagrant/provision.sh`
- Create: `vm/vagrant/run-tests.sh`
- Modify: `Makefile`
- Modify: `README.md`

## Acceptance Criteria

- A developer can run one repo-local command and get a real VM-based validation run.
- The VM boots successfully with the documented provider.
- Provisioning installs all dependencies needed for `make generate`,
  `go test ./...`, and `go test -tags=integration ./test/... -v`.
- The workflow tests the mounted current repository state, not a copied archive.
- Cleanup remains an explicit user action.
