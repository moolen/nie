# nie Optional HTTPS Design

## Goal

Allow `config.yaml` to omit the `https:` block entirely. When omitted, NIE must
disable HTTPS interception and MITM handling while keeping DNS-based hostname
policy enforcement working for standard TLS destinations.

## Approved Behavior

- `https:` may be omitted from the config
- when omitted, NIE performs no HTTPS redirect or MITM interception
- DNS-based hostname policy still works
- `mitm:` remains optional inside an enabled `https:` block

## Design

### Config semantics

Keep `config.HTTPS` as a value type, but track whether the YAML `https:` block
was actually configured.

- omitted `https:` => HTTPS interception disabled
- present `https:` => HTTPS interception enabled and validated
- present-but-empty `https: {}` remains invalid because enabled HTTPS still
  requires explicit intercepted ports

This avoids a wide `*HTTPS` pointer refactor while preserving the distinction
between omitted and configured blocks.

### Runtime behavior

When HTTPS is disabled:

- do not construct MITM HTTP policy
- do not ensure or load a CA
- do not construct the HTTPS proxy or service
- do not install HTTPS redirect rules
- return a runtime service with `HTTPS == nil`

DNS interception, policy matching, trust reconciliation, eBPF, and audit
logging remain active.

### DNS trust behavior

DNS trust entries still need destination ports. Without an enabled `https:`
block there is no configured intercepted port list, so the runtime falls back
to the repository’s standard TLS trust ports:

- `443`
- `8443`

This preserves the existing hostname-based enforcement model for ordinary TLS
traffic while avoiding HTTPS interception.

### Redirect behavior

`internal/redirect.NewManager` should allow DNS-only operation:

- `DNSListenPort` remains required
- `HTTPSPorts` may be empty
- `HTTPSListenPort` is only required when `HTTPSPorts` is non-empty

Rendering and nftables rule generation already naturally skip HTTPS rules when
the HTTPS port list is empty.

## Testing

Add or update tests for:

- config load succeeds when `https:` is omitted
- config load still rejects invalid enabled HTTPS blocks
- redirect manager accepts DNS-only configuration
- app runtime skips HTTPS lifecycle construction when HTTPS is disabled
- app runtime still builds a trust plan that returns default TLS trust ports
  when HTTPS is disabled
