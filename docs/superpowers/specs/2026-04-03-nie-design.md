# nie Design

## Summary

`nie` is a privileged single-host egress filter for Linux. It enforces hostname-based egress policy by running a local DNS forwarder, evaluating queried hostnames against glob-based allow rules, learning IPv4 addresses from allowed DNS responses, and programming those addresses into a pinned eBPF map read by a tc egress classifier.

The initial scope is intentionally narrow:

- single Linux host
- single managed egress interface
- IPv4 only
- classic DNS over UDP/TCP port 53
- default-deny hostname policy
- `enforce` and `audit` runtime modes

## Goals

- Allow outbound connections only when their destination IPv4 address was learned from an allowed DNS lookup.
- Keep hostname policy in userspace where glob matching, logging, and configuration are straightforward.
- Keep packet enforcement in tc/eBPF for low overhead and strong default-deny behavior.
- Support an `audit` mode that exercises the same decision path as enforcement while allowing all traffic and logging what would have been denied.

## Non-Goals

- clustering or multi-host coordination
- container or namespace awareness
- IPv6 or AAAA learning in v1
- TLS-intercepting DNS protocols such as DoH or DoT
- application identity, per-process policy, or user-based policy

## Recommended Approach

The system follows the same broad control-plane/data-plane split used by Cilium's DNS proxy model:

1. Intercept host DNS traffic and send it to a local DNS server.
2. Evaluate the queried hostname against a glob-based allow policy.
3. Forward allowed queries to an upstream resolver.
4. Parse A records from the upstream response.
5. Insert returned IPv4 addresses into a pinned eBPF allow map using TTL-based expiry metadata.
6. Attach a tc egress classifier to the managed interface.
7. Allow egress when the packet is marked as proxy-originated or when its destination IPv4 is present and unexpired in the allow map.
8. Drop unknown or untrusted egress in `enforce`, or allow and log it in `audit`.

This keeps the interface between userspace and kernel small: a packet mark, a pinned allow map, and an event stream for logs.

## Runtime Architecture

### Userspace Components

#### `cmd/nie`

Daemon entrypoint. Loads config, sets up logging, validates privileges, wires subsystems together, and handles startup and shutdown.

#### `internal/config`

Loads and validates `config.yaml`.

#### `internal/policy`

Normalizes hostnames and evaluates them against glob rules.

Responsibilities:

- lowercase normalization
- trailing-dot stripping
- explicit hostname matching
- glob matching for allowed names

#### `internal/dnsproxy`

Runs the local DNS listener and forwards allowed DNS queries to upstream resolvers.

Responsibilities:

- listen on configured address
- accept UDP and TCP DNS on port 53 redirection target
- evaluate queried hostname before forwarding
- in `enforce`, deny policy failures locally and log them
- in `audit`, forward queries even when they would be denied and log `would_deny_dns`
- parse upstream A records and feed IPv4 results into the allow-map writer

#### `internal/ebpf`

Owns loading the tc program, pinning maps, and exposing a small userspace API for map updates and event consumption.

#### `internal/redirect`

Installs and removes host DNS interception rules for UDP/TCP port 53 on the managed host.

#### `internal/runtime`

Coordinates startup ordering and shared dependencies between config, redirect setup, DNS proxy, policy engine, and eBPF lifecycle.

### Kernel Component

#### `bpf/egress.c`

tc egress classifier attached to the configured interface.

Responsibilities:

- allow packets carrying the configured mark used by the DNS proxy
- inspect IPv4 destination address for ordinary traffic
- allow if the destination exists in the allow map and the entry is still valid
- in `enforce`, drop packets that are not trusted
- in `audit`, allow packets that are not trusted and emit a `would_deny_egress` event

## Data Flow

### DNS Path

1. A host process sends a DNS request to its configured resolver.
2. Host firewall redirection rewrites UDP/TCP destination port 53 traffic to the local `nie` DNS server.
3. `nie` extracts the queried hostname and normalizes it.
4. The policy engine checks the hostname against the allow globs in `config.yaml`.
5. If the hostname is denied:
   - `enforce`: respond locally with refusal or a local denial response and log the decision
   - `audit`: log `would_deny_dns` and still forward upstream
6. If the hostname is allowed, forward the request upstream using a marked socket path.
7. Parse the upstream response.
8. For each returned A record, write an allow-map entry keyed by IPv4 destination with expiry metadata derived from DNS TTL.
9. Return the upstream response to the original client.

### Egress Path

1. An outbound IPv4 packet leaves the host on the managed interface.
2. tc egress program runs.
3. If the packet mark matches the configured proxy mark, allow immediately.
4. Otherwise, look up destination IPv4 in the allow map.
5. If the entry exists and is unexpired, allow.
6. If the entry is absent or expired:
   - `enforce`: emit deny event and drop
   - `audit`: emit `would_deny_egress` and allow

## Policy Model

The first version uses a default-deny allowlist model only.

Example `config.yaml`:

```yaml
mode: enforce

interface: eth0

dns:
  listen: "127.0.0.1:1053"
  upstreams:
    - "1.1.1.1:53"
    - "8.8.8.8:53"
  mark: 4242

policy:
  default: deny
  allow:
    - "*.github.com"
    - "github.com"
    - "*.golang.org"
```

### Semantics

- Match against normalized FQDN strings with the trailing dot removed.
- `policy.default` remains explicit in the config, even though only `deny` is supported in v1.
- `policy.allow` is a list of hostname globs.
- Only IPv4 destinations learned from allowed DNS responses are trusted.
- Direct IP egress that did not originate from an allowed DNS answer is denied in `enforce` and logged as `would_deny` in `audit`.
- AAAA responses are ignored in v1 and logged at debug or info level as unsupported.

## Audit Mode

`audit` mode must exercise the same decision engine as `enforce`.

### DNS Behavior

- A hostname that is not allowed is logged as `would_deny_dns`.
- The DNS query is still forwarded upstream.
- Returned IPv4 A records are still learned and inserted into the allow map so that the packet path can be observed realistically.

### Egress Behavior

- The tc program checks marks and allow-map state exactly as it would in `enforce`.
- When a packet is not trusted, it emits `would_deny_egress` and allows it to pass.

This gives operators a dry-run mode that surfaces both hostname-policy misses and packet-path misses without breaking traffic.

## Linux Integration

### DNS Interception

v1 should intercept both UDP and TCP port 53 on the local host. The interception mechanism can be implemented with iptables or nftables, but the redirection layer should be isolated behind a small interface so it can be swapped later.

Design constraints:

- only one managed interface
- only host-local DNS interception
- `nie` itself must be able to send upstream DNS through the same interface without getting trapped or blocked

### Proxy Exemption

The daemon's upstream DNS traffic should use a configured packet mark. The tc program allows packets carrying that mark before consulting the allow map.

This is the simplest and most explicit exemption model for v1:

- no separate out-of-band interface
- no hardcoded destination exemptions
- same interface for ordinary and proxy-originated traffic

## eBPF Maps And Events

### Allow Map

Key:

- destination IPv4 address

Value:

- expiry timestamp or monotonic deadline representation
- optional metadata for debugging such as source hostname hash or flags

The value format should be kept compact and stable because it is shared between userspace and the tc program.

### Event Channel

The tc program should emit structured events for:

- denied egress in `enforce`
- `would_deny_egress` in `audit`

Userspace logs them with interface, destination IPv4, mode, and any available rule context.

## Failure Handling

Preferred v1 behavior:

- Fail closed if tc program or allow-map setup cannot be attached after the system has begun managing traffic.
- Refuse startup if config is invalid, required privileges are missing, or the interface does not exist.
- Treat upstream DNS failure as ordinary DNS failure; do not create allow-map entries when no valid upstream response is received.
- Clamp or sanitize pathological TTL values to avoid unbounded trust windows.

## Project Layout

```text
cmd/nie/main.go
internal/config/
internal/policy/
internal/dnsproxy/
internal/ebpf/
internal/redirect/
internal/runtime/
bpf/egress.c
bpf/include/
```

This decomposition keeps the policy engine, DNS server, redirector, and kernel integration independently testable.

## Testing Strategy

### Unit Tests

- config parsing and validation
- hostname normalization
- glob matching behavior
- DNS allow and deny decisions
- audit-mode DNS behavior
- TTL expiry bookkeeping and allow-map update logic behind an abstract map writer

### Integration Tests

The first implementation should prefer userspace integration tests that do not require tc attachment by default:

- local DNS proxy forwarding against a fake upstream
- allowed hostname inserts learned IPv4 addresses
- denied hostname does not populate trust entries in `enforce`
- audit mode logs `would_deny_dns` and still learns addresses from forwarded queries

Root-required end-to-end tests for tc attachment can be added later behind explicit integration gating.

## Implementation Notes

- Keep the first release IPv4-only.
- Support only classic DNS on UDP/TCP port 53 in v1.
- Treat DoH, DoT, or hardcoded alternate resolvers as ordinary egress that must independently pass policy.
- Keep config small and explicit; avoid rule exceptions until the base flow is solid.
