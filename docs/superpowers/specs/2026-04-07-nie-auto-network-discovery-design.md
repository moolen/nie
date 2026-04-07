# NIE Auto Network Discovery Design

## Goal

Add an unambiguous auto-discovery mode for the protected network interface and DNS upstream servers so the same `nie` config can run across hosts with different interface names and resolver settings, while still failing closed when the host is not safely auto-detectable.

## Problem

`nie` currently requires:

- an explicit protected interface name
- an explicit DNS upstream list

That is brittle on fleets where the host interface name is not stable across instance types or environments. On Linux hosts, names such as `eth0`, `ens5`, and `enp1s0` may all be correct depending on the platform.

The user wants automatic detection only when it is reliable:

- the protected interface should come from routing state rather than string heuristics
- DNS upstreams should come from the host resolver configuration
- ambiguous environments must fail closed instead of guessing

The current runtime also accepts multiple configured DNS upstreams but only uses the first one. Preserving a multi-upstream config shape without fixing that mismatch would keep the operator contract misleading.

## Scope

This change covers:

- a new structured config shape for interface selection
- a new structured config shape for DNS upstream selection
- auto-detection of the protected interface from IPv4 default-route state
- auto-detection of DNS upstreams from `/etc/resolv.conf`
- a resolution phase that turns auto selectors into concrete runtime values before startup
- fail-closed startup errors for ambiguous or unusable auto-detection results
- runtime use of the full resolved DNS upstream list in order
- unit tests for config validation, auto-resolution, and runtime wiring

This change does not cover:

- IPv6 support
- auto-detection of DNS listener addresses
- route-based DNS server discovery
- hot reloading when routes or `/etc/resolv.conf` change at runtime
- heuristic tie-breakers when multiple interface candidates exist

## Config Shape

Replace the plain string fields with explicit selector objects.

### Interface

Explicit:

```yaml
interface:
  mode: explicit
  name: eth0
```

Auto:

```yaml
interface:
  mode: auto
```

Rules:

- `mode` is required
- `name` is required only for `mode: explicit`
- `name` must be empty for `mode: auto`

### DNS Upstreams

Explicit:

```yaml
dns:
  upstreams:
    mode: explicit
    addresses:
      - 1.1.1.1:53
      - 9.9.9.9:53
```

Auto:

```yaml
dns:
  upstreams:
    mode: auto
```

Rules:

- `mode` is required
- `addresses` is required only for `mode: explicit`
- `addresses` must be empty for `mode: auto`
- explicit addresses keep the existing `host:port` validation rules
- the explicit address list remains ordered

## Resolution Model

Config loading and startup split into two phases:

1. Parse and validate selector shape.
2. Resolve selectors into a concrete runtime config.

The rest of the runtime consumes only resolved values. eBPF setup, redirect wiring, preflight validation, and DNS proxy construction should never see `mode: auto`.

Proposed flow:

1. Load YAML into selector-based config structs.
2. Validate config shape and explicit-field invariants.
3. Resolve `interface` and `dns.upstreams`.
4. Validate and build runtime components from the resolved values.

The resolver should return field-specific errors so startup failures point directly at the unresolved selector.

## Interface Auto-Detection

`interface.mode: auto` resolves from IPv4 default-route state.

Design:

- inspect the host routing table for IPv4 default routes
- collect the egress interface for each usable default route entry
- de-duplicate candidate interface names
- require exactly one unique interface name

Success case:

- one unique default-route interface resolves to the protected interface

Failure cases:

- no usable IPv4 default route exists
- multiple default routes resolve to different interfaces
- the resolved interface cannot be looked up
- the resolved interface fails the existing IPv4-only preflight checks

This intentionally avoids interface-name ignore lists such as `docker0`, `lo`, or `veth*`. If those are not the default-route egress path, they are naturally excluded by the routing-based design. If the routing table itself is ambiguous, startup fails.

## DNS Upstream Auto-Detection

`dns.upstreams.mode: auto` resolves from `/etc/resolv.conf`.

Design:

- read the host resolver configuration
- extract `nameserver` entries in file order
- normalize each usable entry to `host:53`
- preserve the resulting address order
- de-duplicate exact duplicate addresses while keeping first-seen order

Usable entries:

- IPv4 nameserver addresses

Filtered entries:

- empty or malformed entries
- loopback nameservers such as `127.0.0.1`
- unspecified addresses
- IPv6 nameservers because `nie` remains IPv4-only in this design

Failure cases:

- `/etc/resolv.conf` cannot be read
- the file cannot be parsed well enough to extract nameservers
- no usable IPv4 nameservers remain after filtering

Loopback resolvers are excluded intentionally. A local stub such as `127.0.0.53` is not a safe upstream target for `nie` because `nie` itself owns the DNS interception path and needs real upstream destinations.

## Runtime Integration

Add a small runtime-config resolver between config loading and `buildRuntimeService`.

Responsibilities:

- accept selector-based config
- resolve interface and DNS upstream selectors
- return a concrete config with:
  - resolved interface name
  - resolved DNS upstream address list

The concrete config should then flow through the existing startup path with minimal changes.

Runtime integration changes:

- preflight validation runs against the resolved interface
- eBPF manager receives the resolved interface
- DNS client configuration receives the resolved upstream list
- DNS forwarding stops silently using only the first upstream and instead tries upstreams in configured order until one succeeds or the list is exhausted

Trying upstreams in order keeps the multi-upstream operator contract honest and makes auto-discovered resolver lists useful beyond the first address.

## Validation And Errors

Config validation should remain strict and field-aware.

Examples:

- `interface.mode` must be one of `explicit` or `auto`
- `interface.name` must be set for `explicit`
- `interface.name` must not be set for `auto`
- `dns.upstreams.mode` must be one of `explicit` or `auto`
- `dns.upstreams.addresses` must contain at least one entry for `explicit`
- `dns.upstreams.addresses` must be empty for `auto`

Resolution errors should preserve field context.

Representative errors:

- `resolve interface: no IPv4 default route found`
- `resolve interface: auto-detect found multiple default-route interfaces: ens5, eth0`
- `resolve dns.upstreams: no usable IPv4 nameservers found in /etc/resolv.conf`
- `resolve dns.upstreams: read /etc/resolv.conf: permission denied`

## Testing Strategy

Follow TDD for the implementation.

### Config Tests

Add coverage for:

- valid explicit interface selector
- valid auto interface selector
- invalid interface mode
- explicit interface missing `name`
- auto interface with unexpected `name`
- valid explicit DNS upstream selector
- valid auto DNS upstream selector
- explicit DNS upstreams missing addresses
- auto DNS upstreams with unexpected addresses

### Resolver Tests

Add focused unit tests around injected dependencies for host state.

Interface resolution:

- one default-route interface resolves successfully
- no default route fails
- multiple default-route interfaces fail
- duplicate routes on the same interface still resolve successfully

DNS upstream resolution:

- `/etc/resolv.conf` with multiple IPv4 nameservers resolves in file order
- duplicate nameservers are de-duplicated without reordering
- loopback, unspecified, IPv6, and malformed entries are filtered out
- no usable nameservers fails
- read errors surface with field context

### Runtime Wiring Tests

Add or update app-level tests so they prove:

- component builders receive the resolved interface
- DNS client wiring receives the full resolved upstream list
- DNS forwarding falls through to later upstreams when an earlier upstream fails
- explicit mode remains behaviorally equivalent aside from the config shape

## Risks And Mitigations

Risk: Linux routing state can contain multiple default routes during failover or policy-routing setups.
Mitigation: fail closed instead of guessing.

Risk: hosts may use local resolver stubs in `/etc/resolv.conf`.
Mitigation: filter loopback entries and fail closed if no real upstream remains.

Risk: preserving multi-upstream config while continuing first-entry-only runtime behavior would surprise operators.
Mitigation: update the DNS client path to honor the resolved upstream order.

Risk: auto-detection logic could become hard to test if it reaches directly into the live system everywhere.
Mitigation: isolate route and resolv.conf access behind small resolver dependencies with focused unit tests.

## Acceptance Criteria

- config supports:
  - `interface.mode: explicit|auto`
  - `dns.upstreams.mode: explicit|auto`
- `interface.mode: auto` resolves from IPv4 default-route state and fails closed on ambiguity
- `dns.upstreams.mode: auto` resolves usable IPv4 nameservers from `/etc/resolv.conf`
- auto-detected loopback or IPv6-only resolver entries are not used
- startup errors identify whether interface or DNS upstream auto-resolution failed
- resolved interface and upstreams are fed into the existing runtime before preflight and component construction
- DNS forwarding honors the full configured or resolved upstream list in order
- unit tests cover config shape validation, interface resolution, DNS upstream resolution, and runtime wiring
