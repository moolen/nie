# NIE Smoke Audit Docker Domains Design

## Goal

Add a root-gated integration smoke test that proves `nie` in `audit` mode captures the outbound domains used by a real pinned `docker build`, and assert the exact required domains for that pinned build input.

## Problem

The current smoke coverage proves:

- audit mode logs denied DNS, egress, and HTTPS traffic on loopback
- enforce mode blocks unknown traffic until DNS learning
- long-lived DNS trust cleanup behaves correctly for rotated TCP flows

What it does not prove is that `nie` can observe and log the domain activity from a real-world build workload on the host's actual outbound interface. The user specifically wants a smoke step that:

1. runs `nie` in `audit` mode
2. clones a pinned `spectre` repository revision
3. runs `docker build`
4. greps audit logs for the domains implied by that pinned `Dockerfile`

That behavior cannot be meaningfully covered by the existing loopback-only audit smoke because `docker build` egresses via the runner's default outbound interface, not `lo`.

## Scope

This change covers:

- one new root-gated integration smoke test for audit-mode host egress capture during a real `docker build`
- helper logic to detect the default outbound interface
- helper logic to clone a pinned external repository revision into a temp dir
- helper logic to extract normalized audited domains from `nie` logs
- exact required-domain assertions for the pinned `spectre` build
- CI wiring so the smoke workflow runs the new integration test

This change does not cover:

- broad support for arbitrary external repos in smoke config
- a generic URL capture/export feature in `nie`
- asserting the full observed hostname set from Docker/CDN behavior
- changing the current loopback audit/enforce smoke behavior

## Pinned External Input

Use the pinned `spectre` revision:

```text
e49f8e0899616842cff5441bc4d9ee10c0667f20
```

The test clones `https://github.com/moolen/spectre`, checks out that exact revision, and runs `docker build` against the repository root `Dockerfile`.

Pinning is required so the asserted domain set stays tied to a known build graph rather than drifting with upstream changes.

## Domain Assertion Model

For the pinned `spectre` `Dockerfile`, the test must observe at least these exact audited domains:

- `auth.docker.io`
- `registry-1.docker.io`
- `registry.npmjs.org`
- `proxy.golang.org`
- `sum.golang.org`
- `dl-cdn.alpinelinux.org`

Rationale:

- base-image pulls require Docker Hub auth and registry access
- `npm ci` requires npm registry access
- `go mod download` requires Go proxy and checksum database access
- Alpine package installation requires the Alpine CDN

The test should:

- normalize captured hostnames into a set
- fail if any required domain is missing
- log the full observed domain set for debugging
- allow extra domains without failing

This keeps the test exact about what the pinned build must exercise while avoiding brittleness from incidental registry/CDN behavior.

## Network Topology Design

Unlike the existing loopback smoke, this test must protect the host's default outbound interface because `docker build` network traffic will not traverse `lo`.

Design:

- detect the default route interface at test runtime
- validate that the interface is IPv4-only under the current product rules
- start `nie` in `audit` mode using that interface
- issue host-side operations (`git clone`, `docker build`) while `nie` is active

Environment constraints:

- root is required
- Docker CLI and daemon must be available
- outbound internet access must be available
- the current host must satisfy `nie`'s IPv4-only protected-interface validation

If Docker is missing or unusable, the test should skip with a precise reason rather than fail ambiguously.

## Test Flow Design

Add a new root-gated integration test to `test/smoke_test.go`.

Proposed flow:

1. Verify root privileges.
2. Verify Docker is installed and usable.
3. Determine the default outbound interface.
4. Start `nie` in `audit` mode on that interface.
5. Wait for pinned datapath and redirect state, as in existing smoke tests.
6. Clone pinned `spectre` into a temp dir.
7. Run `git checkout` for the pinned revision.
8. Run `docker build` against the pinned checkout under a bounded timeout.
9. Terminate `nie`.
10. Parse `nie` logs into a normalized hostname set.
11. Assert that the required exact domains are present.
12. Log the observed audited hostnames to make failures debuggable.

The test should not depend on Docker build success being derived from `nie`; it should require the build itself to succeed so the domain expectations correspond to a complete pinned build path.

## Helper Design

### Default Route Interface Detection

Add a small helper in the integration test package that discovers the default outbound interface using the system routing table, preferably through `ip route get` or `ip route show default`.

Requirements:

- return an interface name
- fail with a precise error if no default route can be determined
- keep the implementation test-local rather than introducing new production dependencies

### Pinned Repo Checkout

Add a helper that:

- runs `git clone --depth 1` for the target repo into a temp dir
- fetches the pinned commit if needed
- checks out the exact pinned revision

The helper should keep command output available in failure messages.

### Audited Domain Extraction

Add a helper that parses hostname-bearing audit log lines from `nie` output.

Sources to inspect:

- `would_deny_dns` entries with `host=...`
- `would_deny_https` entries with `host=...`

Normalization:

- trim any trailing dot from DNS-style hostnames
- lowercase
- deduplicate into a set

The helper should be deterministic and covered by focused unit tests.

## CI Design

Extend the existing smoke workflow step so it also runs the new integration test by name.

Because this test uses the host's default outbound interface instead of loopback:

- do not reuse the loopback-only opt-in guard
- keep the existing loopback IPv4-only preparation for the older loopback smoke
- ensure the smoke workflow still remains root-gated

The workflow should continue to fail if the new integration test fails.

## Testing Strategy

Follow TDD:

1. Add focused unit tests for audited-domain extraction and normalization.
2. Add focused tests for any helper that computes expected domain behavior.
3. Add the failing integration smoke test.
4. Update CI workflow invocation to include the new test.
5. Implement the minimal helpers and smoke logic.
6. Run focused test packages, then `go test ./... -count=1`.
7. Run the targeted root-gated integration command where possible.

## Risks And Mitigations

Risk: outbound interface detection could be environment-specific.
Mitigation: use a minimal Linux-specific shell-backed helper inside the integration test package and fail with explicit diagnostics.

Risk: Docker registries and CDNs may introduce incidental extra domains.
Mitigation: assert only the exact required domain subset, but log the full observed set.

Risk: the host's default outbound interface may have IPv6 configured, which `nie` intentionally rejects today.
Mitigation: keep the test fail/skip behavior explicit so the environment problem is obvious rather than silently weakening product behavior.

Risk: external network or Docker daemon flakiness could make the test noisy.
Mitigation: bound clone/build timeouts, surface command output on failure, and keep the pinned repo small and deterministic.

## Acceptance Criteria

- a new root-gated integration smoke test runs `nie` in audit mode on the default outbound interface
- the test clones pinned `spectre` revision `e49f8e0899616842cff5441bc4d9ee10c0667f20`
- the test runs `docker build` successfully against that pinned checkout
- audited domains are extracted from `nie` logs and normalized deterministically
- the test asserts presence of:
  - `auth.docker.io`
  - `registry-1.docker.io`
  - `registry.npmjs.org`
  - `proxy.golang.org`
  - `sum.golang.org`
  - `dl-cdn.alpinelinux.org`
- CI smoke wiring runs the new test
- `go test ./... -count=1` passes
