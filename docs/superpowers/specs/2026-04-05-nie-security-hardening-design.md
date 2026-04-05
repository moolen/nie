# nie Security Hardening Design

## Goal

Close three concrete security gaps in the current single-host datapath without
expanding product scope:

1. Prevent HTTPS policy bypass via mismatched HTTP `Host` or HTTP/2 `:authority`
   when SNI was allowed.
2. Ensure stalled pre-classification TLS connections cannot keep the MITM
   service running indefinitely or block shutdown.
3. Fail startup closed when the protected interface has IPv6 addresses assigned,
   because the current enforcement path is IPv4-only.

## Scope

This design intentionally stays within the current v1 model:

- single host
- single protected interface
- IPv4 enforcement only
- no new IPv6 datapath support
- no new policy surface

## Design

### 1. HTTPS Authority Must Match Classified SNI

The MITM proxy already classifies TLS connections by normalized SNI and applies
policy based on that host. The proxy must also validate the HTTP authority seen
after decryption:

- HTTP/1: validate `req.Host`
- HTTP/2: validate `req.Host` as populated from `:authority`

If normalized authority does not exactly match the classified SNI host:

- `enforce`: deny the request
- `audit`: log a `would_deny_https` entry with a dedicated mismatch reason and
  still forward it

The upstream request should continue to preserve the original authority value in
audit mode so existing audit semantics remain “allow but log”.

### 2. Bound and Stoppable Pre-Classification Connections

The HTTPS service currently accepts TCP connections and classifies them before
passing them to the proxy. That stage must be hardened so idle or malicious
clients cannot block shutdown:

- add a configurable client-hello timeout with a safe default
- apply a read deadline before client-hello peeking
- clear the deadline before handing the connection to the proxy
- track accepted connections in the service
- on `Stop()`, close the listener and all tracked active connections before
  waiting for goroutines

This ensures both organic stalls and deliberate slowloris-style local clients
are bounded.

### 3. IPv6 Fail-Closed Startup Validation

`nie` is intentionally IPv4-only today, but an interface with IPv6 addresses can
still carry unmanaged outbound traffic. Startup must refuse that configuration:

- inspect the configured protected interface before building the runtime
- if any IPv6 address is assigned to that interface, return an explicit startup
  error
- document the constraint in the README

This is a deliberate fail-closed behavior until a real IPv6 datapath exists.

## Testing

Add regression coverage for:

- HTTP/1 authority mismatch denied in enforce mode
- HTTP/2 authority mismatch denied in enforce mode
- authority mismatch logged and allowed in audit mode
- MITM service stop returns promptly with a stalled pre-client-hello connection
- MITM service drops idle clients after the configured client-hello timeout
- runtime build fails when interface validation reports IPv6 assigned

