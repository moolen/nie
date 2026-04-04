# nie HTTPS MITM Design

## Summary

Add transparent selective HTTPS interception to `nie` for configured destination
ports, with policy decisions based on SNI, HTTP method, and request path. The
system should terminate downstream TLS using a locally generated or reused root
CA, validate upstream TLS with the normal system trust store, and apply HTTP
request policy after decryption.

This is host-wide, not per-process. HTTPS traffic on configured ports is
intercepted first, then decided at the HTTP policy layer. If no MITM rule
matches, existing non-MITM hostname policy still applies as fallback. If nothing
matches, the existing default deny or audit behavior remains the final outcome.

## Goals

- Transparently intercept HTTPS traffic on configured destination ports.
- Support selective policy by hostname, target port, HTTP method, and request
  path.
- Generate a local root CA if absent, reuse it if present, and persist it at a
  well-known location.
- Require trust-store installation to be handled outside `nie`.
- Deny or audit TLS connections without usable SNI, configured in `config.yaml`.
- Use system trust for upstream TLS validation and fail closed on validation
  errors.
- Preserve current hostname-based non-MITM policy as fallback when no MITM rule
  matches.

## Non-Goals

- Per-process or namespace-specific interception
- Body inspection in v1
- Arbitrary non-HTTP TLS interception
- Automatic installation of the local root CA into system or application trust
  stores
- Header rewriting or response modification in v1
- Transparent interception on every TCP port

## User Intent

The desired behavior is transparent host-level HTTPS control with policy based on
decrypted HTTP request metadata. The user wants:

- HTTPS interception to be enabled on configured ports
- all HTTPS on those ports to be intercepted first
- policy based on SNI hostname, HTTP method, and path
- no body inspection
- non-MITM rules to remain relevant as fallback
- missing-SNI handling to be configurable, with deny as the default choice
- root CA material to be written to a well-known path so users can distribute it
  separately, for example into containers

## Configuration Model

Extend `config.yaml` with a dedicated HTTPS section:

```yaml
mode: enforce
interface: eth0

dns:
  listen: 127.0.0.1:1053
  upstreams:
    - 1.1.1.1:53
  mark: 4242

policy:
  default: deny
  allow:
    - github.com
    - "*.github.com"

https:
  ports:
    - 443
  sni:
    missing: deny
  ca:
    cert_file: /var/lib/nie/ca/root.crt
    key_file: /var/lib/nie/ca/root.key
  mitm:
    default: deny
    rules:
      - host: api.github.com
        port: 443
        methods: ["GET"]
        paths:
          - /repos/**
        action: allow
      - host: api.github.com
        port: 443
        methods: ["POST"]
        paths:
          - /repos/**
        action: audit
```

### Semantics

- `https.ports`
  - all TCP traffic to these destination ports is treated as HTTPS interception
    candidates
- `https.sni.missing`
  - configurable behavior for absent or unparsable SNI
  - v1 actions: `deny`, `audit`
- `https.ca.cert_file` and `https.ca.key_file`
  - well-known persisted CA location
  - generate if missing, reuse if present
- `https.mitm.rules`
  - evaluated on decrypted HTTP request metadata
  - rule keys: `host`, `port`, `methods`, `paths`, `action`
- `https.mitm.default`
  - HTTP-layer fallback for intercepted HTTPS if no MITM rule matches
  - after that, normal non-MITM hostname policy may still allow pass-through if
    configured

## Traffic Model

### High-Level Flow

1. TCP traffic to a configured HTTPS destination port is redirected to `nie`.
2. `nie` reads enough of ClientHello to parse SNI.
3. If SNI is absent or unusable:
   - apply `https.sni.missing`
   - in `enforce`, deny
   - in `audit`, log and allow only if configured behavior says audit
4. If SNI exists:
   - terminate downstream TLS using a generated leaf certificate for the SNI
   - establish upstream TLS using the system trust store
   - parse the HTTP request line and headers
   - evaluate MITM policy on `host + port + method + path`
5. If a MITM rule allows:
   - proxy upstream request and downstream response
6. If a MITM rule denies:
   - reject locally
7. If a MITM rule audits:
   - log and forward
8. If no MITM rule matches:
   - apply the remaining non-MITM hostname policy
   - if still unmatched, deny or audit according to global mode/defaults

### HTTPS Interception Scope

Intercept all HTTPS on configured ports, not only preselected hostnames. That is
required because policy decisions depend on decrypted HTTP metadata and cannot be
made correctly before the TLS handshake unless the system intercepts first.

### Fallback Behavior

If MITM rules do not match, existing normal hostname policy remains meaningful.
That preserves the user’s requirement that “the remaining rules should apply.”

## Runtime Architecture

Add a distinct HTTPS interception pipeline alongside the existing DNS path.

### Redirect Manager

Extend the current redirect manager so it can:

- keep DNS redirect behavior
- add HTTPS redirect rules for configured destination ports
- maintain explicit bypass handling where needed for `nie`’s own traffic

The DNS and HTTPS redirect paths should remain separate in code and config.

### TLS Acceptor / Classifier

This component:

- accepts redirected TCP connections for configured HTTPS ports
- inspects ClientHello without fully completing the handshake yet
- extracts SNI
- identifies original destination port for policy evaluation
- applies missing-SNI behavior before HTTP interception continues

### CA Manager

This component:

- ensures the CA cert and key exist at configured paths
- generates them if absent
- loads and reuses them if present
- writes them with locked-down permissions

It must not attempt trust-store installation.

### MITM Proxy

This component:

- issues leaf certificates for SNI hostnames on demand
- terminates downstream TLS
- creates upstream TLS sessions using the system trust store
- parses HTTP request line and headers
- evaluates HTTP policy
- proxies request and response streams when allowed

### HTTP Policy Engine

Separate from the current DNS hostname policy engine.

It should support:

- exact or glob host matching
- exact destination port matching
- method matching against an explicit set
- path glob matching
- actions: `allow`, `deny`, `audit`

It should not inspect bodies in v1.

### Fallback Policy Bridge

This layer decides what happens when HTTPS was intercepted successfully but no
MITM rule matched:

- first consult configured MITM default
- then apply existing non-MITM hostname rules as fallback
- if still unmatched, defer to existing deny or audit semantics

## Certificate Model

### Root CA Lifecycle

- if configured CA files do not exist, generate them on startup
- if they do exist, reuse them unchanged
- persist them at the configured well-known location

### Leaf Certificate Issuance

- generate leaf certs per SNI hostname on demand
- sign them with the local root CA
- keep validity periods reasonable and implementation simple in v1

### Upstream Validation

- always validate upstream server certificates with the system trust store
- on validation failure, deny the request

## Policy Evaluation Model

### Pre-HTTP Stage

- destination port must be in `https.ports`
- SNI must be present unless policy says otherwise

### HTTP Stage

Evaluate MITM rules on:

- SNI hostname
- original destination port
- HTTP method
- request path

Possible actions:

- `allow`
- `deny`
- `audit`

### Missing or Invalid Data

- missing SNI: configurable `deny` or `audit`
- invalid TLS or unparsable ClientHello on configured HTTPS port: fail closed
- invalid HTTP request after interception: deny

## Logging

Add structured logs for:

- CA generation or reuse
- missing-SNI deny or audit
- upstream TLS validation failures
- HTTP policy decisions
- fallback from MITM policy to normal hostname policy

Potential event names:

- `would_deny_https_sni_missing`
- `would_deny_https_request`
- `https_request_denied`
- `https_request_allowed`

## Failure Handling

- if CA generation or load fails, HTTPS MITM startup fails
- if redirect install for HTTPS ports fails, startup fails
- if ClientHello parsing fails on an intercepted HTTPS flow, deny
- if upstream TLS validation fails, deny
- if HTTP parsing fails, deny
- if the traffic on a configured HTTPS port is not valid TLS/HTTP, deny

Fail closed by default.

## Security Boundaries

- the local CA private key is a high-value secret and must be stored with strict
  permissions
- `nie` does not manage trust-store installation
- decrypted HTTP request metadata is visible to the policy engine and logs, so
  logging should remain metadata-focused and avoid body capture
- upstream TLS validation remains mandatory to avoid silently proxying to invalid
  endpoints

## Testing Strategy

### Unit Tests

- config parsing and validation for the new `https` section
- CA generation and reuse
- SNI extraction from ClientHello
- method and path policy matching
- fallback behavior between MITM and normal hostname rules
- upstream validation failure handling

### Host Integration Tests

- HTTPS interception on configured ports
- deny when SNI is missing
- deny when upstream certificate validation fails
- allow, deny, and audit behavior on method/path policy
- fallback to non-MITM hostname policy

### VM Tests

- CA files generated at the configured well-known path
- long-lived process can reach allowed HTTPS path through MITM
- denied HTTPS paths are blocked
- repeated start-stop lifecycle cleanup still restores networking
- VM behavior remains deterministic using local test fixtures

## Operational Considerations

- users must manually trust the generated CA where needed
- containers may need the CA mounted separately from the host path
- only configured HTTPS ports are intercepted
- non-HTTPS traffic on those ports will fail closed in v1

## Implementation Staging

This should be built in stages:

1. HTTPS config schema + CA manager + startup skeleton
2. HTTPS redirect path + ClientHello/SNI parsing
3. MITM TLS termination + upstream validation
4. HTTP method/path policy engine + fallback bridge
5. Host and VM validation

## Acceptance Criteria

- `nie` transparently intercepts HTTPS on configured destination ports
- local CA files are generated if absent and reused if present
- missing-SNI behavior is configurable and deny is supported
- upstream TLS validation uses system trust and fails closed
- HTTP policy supports host, port, method, and path matching
- actions `allow`, `deny`, and `audit` work for MITM rules
- non-MITM hostname policy still applies when no MITM rule matches
- CA trust-store installation remains external to `nie`
