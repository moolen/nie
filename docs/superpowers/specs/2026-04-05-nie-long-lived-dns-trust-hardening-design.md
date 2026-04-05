# NIE Long-Lived DNS Trust Hardening Design

## Goal

Make long-lived deployments operationally safe by:

- exposing trust cleanup timing as explicit configuration
- proving end to end that DNS rotation does not break active TCP flows
- proving stale trusted IPs are eventually removed after those flows drain

## Problem

The current long-lived DNS trust implementation fixes the additive firewall problem by reconciling hostname answers into desired state and pruning stale destinations. That closes the main correctness gap, but two operator-facing concerns remain:

1. Trust cleanup timing is not configurable even though `trustsync.Service` already supports `MaxStaleHold` and `SweepInterval`.
2. The repository does not yet have an end-to-end test that demonstrates the specific behavior we care about in production: a hostname rotates from IP A to IP B, existing TCP flows to A keep working, new flows use B, and A is eventually removed from the trusted datapath after the flow closes.

## Scope

This change covers:

- config surface for trust cleanup timing
- config validation and runtime wiring
- documentation updates
- one root-gated end-to-end test for DNS rotation plus flow drain

This change does not cover:

- new DNS-learned UDP trust behavior
- IPv6 support
- exposing conntrack implementation details as configuration
- changing the current trust model for HTTPS-only learned ports

## Configuration Design

Add a new top-level config block:

```yaml
trust:
  max_stale_hold: 2m
  sweep_interval: 15s
```

Fields:

- `trust.max_stale_hold`: optional duration string. Extra minimum time to keep a destination in stale state before cleanup is allowed. `0s` means no additional hold beyond conntrack and lease semantics.
- `trust.sweep_interval`: optional duration string. How often the background pruner checks for stale destinations.

Validation:

- both values use Go duration syntax
- both must be non-negative
- zero is allowed
- omitted values preserve existing behavior

Defaults:

- `max_stale_hold` defaults to `0`
- `sweep_interval` defaults to the current trustsync default of `30s`

Rationale:

- these settings govern trust lifecycle rather than DNS transport, so they belong in `trust:` instead of `dns:`
- operators can tune cleanup aggressiveness for different environments without changing code

## Runtime Design

`internal/config` will parse the new `trust` block into typed duration fields.

`internal/app/build.go` will pass those values into `trustsync.New(...)`:

- `MaxStaleHold: cfg.Trust.MaxStaleHold`
- `SweepInterval: cfg.Trust.SweepInterval`
- retain the existing deleter wiring

No behavior changes when the config block is absent.

The current reconciler keeps marking learned destinations as `trustsync.ProtocolTCP`. That remains unchanged in this work because the active requirement is safe cleanup for HTTPS/TCP flows learned from DNS. Protocol-aware learned UDP trust can be treated as a separate feature later.

## End-to-End Test Design

Add one root-gated integration test to the existing harness in `test/smoke_test.go`.

Test topology:

- start two fixture endpoints on distinct loopback IPv4 addresses, IP A and IP B
- start a fake DNS upstream that initially answers the allowed hostname with IP A, then later rotates to IP B
- configure `nie` in enforce mode with a short `trust.sweep_interval` and `trust.max_stale_hold: 0s`

Test sequence:

1. Start `nie`.
2. Resolve the allowed hostname and verify it learns IP A.
3. Open a long-lived TCP connection to IP A and confirm traffic succeeds.
4. Rotate the upstream answer to IP B and resolve the hostname again.
5. Verify a new TCP connection to IP B succeeds.
6. Verify the existing TCP connection to IP A still succeeds after rotation.
7. Close the old TCP connection.
8. Wait until direct new TCP connections to IP A are denied, showing that stale trust was eventually removed after flow drain.

Assertions:

- active established flow to A survives rotation
- new flow to B works after the second DNS answer
- stale A is not immediately removed while conntrack still shows the active flow
- stale A is eventually removed after the flow closes

Implementation notes:

- prefer exercising behavior through real network traffic rather than reading internal trust state
- keep the rotation mechanism deterministic by making the fake upstream answer selectable by the test
- reuse existing probe helpers where possible

## Testing Strategy

Follow TDD strictly:

1. Add failing config parsing and validation tests.
2. Add failing app wiring tests proving `buildRuntimeService` passes trust settings into the shared trust service.
3. Add the failing integration test for DNS rotation and flow drain.
4. Implement the minimal production changes.
5. Run focused package tests, then `go test ./... -count=1`.

## Documentation

Update:

- `config.yaml` sample to show the optional `trust:` block
- `README.md` configuration section to document the new settings
- `README.md` DNS interception flow section to clarify that cleanup timing is operator-tunable via `trust.max_stale_hold` and `trust.sweep_interval`

## Risks And Mitigations

Risk: very small sweep intervals could create unnecessary conntrack churn.
Mitigation: keep defaults conservative and validate only non-negative durations, not overly opinionated minimums.

Risk: the integration test could be flaky if it depends on timing races.
Mitigation: use explicit DNS rotation control, polling helpers, and short but bounded waits around flow drain.

Risk: operators may treat `max_stale_hold=0s` as immediate deletion for TCP.
Mitigation: documentation must state that active TCP conntrack entries still block deletion even when hold time is zero.

## Acceptance Criteria

- config accepts an optional top-level `trust:` block with `max_stale_hold` and `sweep_interval`
- invalid trust durations are rejected during config load
- runtime wiring passes trust config into the trust lifecycle service
- end-to-end test demonstrates safe rotation and eventual stale cleanup
- `go test ./... -count=1` passes
