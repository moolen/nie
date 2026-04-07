# nie CIDR Allow Design

## Goal

Add a narrow `policy.cidr_allow` configuration surface that lets operators
declare IPv4 CIDRs or single IPv4 addresses, together with a protocol, that
should always pass the L3/L4 egress policy through the tc/eBPF datapath.

## Approved Behavior

- `policy.cidr_allow` is optional
- each rule contains:
  - `cidr`
  - `protocol`
- `cidr` accepts IPv4 CIDRs and plain IPv4 addresses
- plain IPv4 addresses normalize to `/32`
- `protocol` accepts:
  - `tcp`
  - `udp`
  - `icmp`
  - `any`
- invalid CIDRs, IPv6 entries, invalid protocols, and duplicate normalized
  rules fail config loading

## Design

### Config semantics

Extend `config.Policy` with a narrow `CIDRAllow` list:

```yaml
policy:
  cidr_allow:
    - cidr: 10.0.0.0/8
      protocol: tcp
    - cidr: 10.20.30.40
      protocol: udp
    - cidr: 10.30.0.0/16
      protocol: any
```

Normalization and validation happen during `config.Load()`:

- trim whitespace from `cidr` and `protocol`
- parse plain IPv4 as `/32`
- reject IPv6 networks and IPv6 addresses
- canonicalize parsed CIDRs so duplicate rules can be detected reliably

This keeps the config surface intentionally narrow and avoids introducing the
broader port and ICMP sub-rule shape documented as future work in `README.md`.

### Runtime behavior

Expanding CIDRs into one allow-map entry per IPv4 is not viable for real
networks, so static CIDR rules need their own kernel-visible representation.

Add a second pinned eBPF map:

- key: IPv4 LPM trie prefix
- value: protocol mask

The tc classifier should check this CIDR map before falling back to the
existing DNS-learned exact allow-map. If the destination IPv4 matches a CIDR
entry and the packet protocol matches the stored protocol mask, the packet
passes immediately.

This keeps static CIDR rules separate from DNS-learned dynamic trust managed by
`trustsync`, while making CIDR matching scale to large prefixes.

### CIDR protocol semantics

Store the configured protocol as a compact mask in the eBPF CIDR map:

- `tcp`
- `udp`
- `icmp`
- `any`

`protocol: any` should allow all IP protocols within the matching prefix.

### Userspace wiring

Expose a dedicated `CIDRAllowWriter` from `internal/ebpf` that writes normalized
prefix rules into the pinned CIDR map. Add a dedicated runtime lifecycle in
`internal/app` that:

- converts `config.Policy.CIDRAllow` into `ebpf.CIDRAllowRule` values
- writes them after the eBPF manager starts and before DNS/redirect traffic
  begins
- fails startup if CIDR-map preload fails
- performs no shutdown cleanup, since the eBPF manager already removes pinned
  NIE state on stop

### App wiring

`internal/app/build.go` should build the static CIDR lifecycle after the eBPF
manager is constructed. The runtime service startup order should stay:

1. eBPF
2. static CIDR preload
3. dynamic trust service
4. DNS
5. HTTPS
6. redirect

That guarantees the static always-allow entries are present before any
forwarded traffic is emitted.

## Testing

Add or update tests for:

- config load accepts valid `policy.cidr_allow` entries
- config load normalizes plain IPv4 addresses to `/32`
- config load rejects invalid CIDRs, IPv6 inputs, invalid protocols, and
  duplicates
- eBPF CIDR writer encodes normalized prefixes and protocol masks correctly
- app runtime preloads the expected CIDR rules on service start
- runtime startup fails closed when CIDR preload fails
- docs and sample config reflect the narrow initial shape
