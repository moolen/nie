# nie

`nie` is a single-host Linux egress policy agent. It follows the same basic model as Cilium's DNS proxy path: intercept DNS, evaluate the queried hostname against an allow policy, forward the request upstream, learn trusted IPv4 destinations from A answers, and let a tc egress program enforce default-deny for unknown destinations.

## Scope

- single host
- single protected interface
- IPv4 only in v1
- classic DNS over UDP/TCP port 53 only
- learns A records only; AAAA answers are ignored
- refuses to start if the protected interface has IPv6 addresses assigned

## Current Status

`cmd/nie` now wires the full native runtime lifecycle:

- an eBPF manager that prepares bpffs, loads/pins runtime objects, and attaches the tc egress classifier
- a redirect manager that installs DNS interception rules with native nftables APIs
- a DNS proxy that forwards queries, enforces policy, and writes trusted A-record destinations into the live eBPF allow map

The daemon does not use shell-out `iptables`/`tc` orchestration for normal startup. True `iptables-legacy`-only hosts are explicitly unsupported.

## Configuration

`config.yaml` uses explicit `host:port` listener addresses, selector-based interface and DNS upstream config, glob-based hostname policy, optional HTTPS interception policy, and optional outbound ICMP policy:

```yaml
mode: enforce
interface:
  mode: auto

dns:
  listen: 127.0.0.1:1053
  upstreams:
    mode: auto
  mark: 4242

trust:
  max_stale_hold: 0s
  sweep_interval: 30s

policy:
  default: deny
  allow:
    - github.com
    - "*.github.com"
    - "**.githubusercontent.com"
  cidr_allow:
    - cidr: 10.0.0.0/8
      protocol: tcp
      ports:
        - 443
        - 8443
        - 10000-10100
    - cidr: 10.20.0.0/16
      protocol: udp
      ports:
        - 53
        - 123
    - cidr: 10.30.0.0/16
      protocol: any
    - cidr: 10.40.0.0/16
      protocol: icmp
      icmp:
        allow:
          - echo-request
          - type: 3
            code: 4

https:
  listen: 127.0.0.1:9443
  ports:
    - 443
    - 8443
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
        methods:
          - GET
          - HEAD
        paths:
          - /meta
          - /repos/**
        action: allow
      - host: uploads.github.com
        port: 443
        methods:
          - POST
        paths:
          - /repos/**/releases
        action: audit

icmp:
  outbound:
    default: deny
    allow:
      - echo-request
      - type: 3
        code: 4
```

The entire `https:` block is optional. When omitted, NIE disables HTTPS
redirect/MITM interception entirely but still applies DNS-based hostname policy
to standard TLS destinations on ports `443` and `8443`.

Selector modes:

- `interface.mode: explicit` requires `interface.name`
- `interface.mode: auto` resolves the protected interface from IPv4 default-route state and fails closed if there is no default route or if multiple default routes use different interfaces
- `dns.upstreams.mode: explicit` requires `dns.upstreams.addresses`
- `dns.upstreams.mode: auto` reads usable IPv4 nameservers from `/etc/resolv.conf`, filters loopback / unspecified / IPv6 entries, and fails closed if no usable upstream remains

Explicit examples:

```yaml
interface:
  mode: explicit
  name: eth0

dns:
  upstreams:
    mode: explicit
    addresses:
      - 1.1.1.1:53
      - 9.9.9.9:53
```

If `icmp.outbound` is omitted, NIE keeps the current trust-based ICMP behavior. When
it is present, outbound ICMPv4 is decided only by the ICMP policy. `default: audit`
allows unmatched ICMP but emits `would_deny_egress` logs with `icmp_type`,
`icmp_code`, and `icmp_metadata_valid`.

`policy.cidr_allow` is a direct egress allow path for IPv4 CIDRs. Matching CIDR
rules take precedence over DNS-learned hostname trust. `protocol: any` is broad
and intentionally unqualified. Matching CIDR rules only bypass HTTPS MITM for
allowed TCP flows to configured intercepted HTTPS ports; UDP to those ports
still follows the existing non-HTTP deny/audit path. For non-matching non-CIDR
traffic, `enforce` still drops by default and `audit` still allows and logs.

`trust` configures how NIE prunes stale DNS-learned destinations. `max_stale_hold`
adds optional extra time before a stale destination is eligible for removal, and
`sweep_interval` controls how often the background stale-destination cleanup runs.
`max_stale_hold: 0s` means there is no additional hold beyond built-in lease and
flow checks, but active TCP conntrack entries still prevent pruning until those
flows drain. Cleanup cadence is operator-tunable via `sweep_interval`; when
omitted, NIE keeps the default conservative sweep behavior.

For intercepted HTTPS, NIE classifies the TLS connection by SNI and then also
requires the decrypted HTTP `Host` / HTTP/2 `:authority` to normalize to the
same hostname. In `enforce`, mismatches are denied. In `audit`, they are
forwarded but logged as `would_deny_https` with `reason=authority_mismatch`.

Glob semantics:

- `github.com`: exact hostname
- `*`: any non-empty valid hostname
- `*.example.com`: exactly one label under `example.com`
- `**.example.com`: one-or-more labels at any depth under `example.com`

## DNS Interception Flow

1. `nie` binds the local DNS proxy on `dns.listen`.
2. On startup, `nie` creates an `inet` nftables table (`nie`) and output NAT chain (`output`) that redirect host UDP/TCP port 53 traffic to the configured listener port.
3. The proxy normalizes the queried hostname and matches it against `policy.allow`.
4. In `enforce`, denied names are answered locally with `REFUSED`.
5. In `audit`, denied names are still forwarded upstream and logged as `would_deny_dns`.
6. Relevant A-record answers for the queried hostname, or for names reached through an in-answer CNAME chain, are reconciled into trusted IPv4 entries for the eBPF allow map per hostname over time (not append-only) and only on configured intercepted HTTPS / MITM service ports.
7. Cleanup is protocol-aware and tunable via `trust.max_stale_hold` and `trust.sweep_interval`: stale UDP destinations age out by DNS lease timing plus any configured stale hold, while stale TCP destinations are removed only after conntrack indicates no active flows, so old TCP destinations may remain trusted briefly while flows drain even with `max_stale_hold: 0s`.
8. When more than one DNS upstream is configured or auto-discovered, `nie` tries them in order until one returns a response.
9. The tc egress program uses `dns.mark` as a bypass mark for proxy-originated DNS traffic.

## Runtime Lifecycle

- before runtime construction, `nie` resolves `interface.mode` and `dns.upstreams.mode` into concrete runtime values and fails closed on ambiguous or unusable auto-detection.
- eBPF startup ensures `/sys/fs/bpf` exists and mounts `bpffs` when needed, then prepares `/sys/fs/bpf/nie`, loads objects, configures mode/mark, pins maps, and attaches tc egress on the resolved interface.
- after resolution, `nie` validates that the protected interface is IPv4-only and fails closed if IPv6 addresses are assigned.
- Redirect startup detects nftables availability and installs only `nie`-owned DNS redirect rules.
- On shutdown, `nie` stops DNS first, then removes redirect rules/chains/tables it owns, detaches tc egress, closes objects, removes pinned state under `/sys/fs/bpf/nie`, and removes clsact when it created it.
- If conflicting preexisting `nie` redirect objects are present, startup/shutdown surfaces explicit errors instead of mutating unknown state.

## Modes

- `enforce`: default deny. Unknown or untrusted egress should be dropped, and denied DNS queries are refused locally.
- `audit`: allow traffic but emit `would_deny_dns` and `would_deny_egress` logs for flows that would have been blocked.

## ICMP Notes

- `icmp.outbound` is outbound-only.
- It applies only to ICMPv4. ICMPv6 and NDP are unchanged by this policy surface.
- PMTU-related behavior is expected to remain unaffected because inbound ICMP handling is out of scope.

## Privileges

Run `nie` as root for now. Native nftables and tc/BPF lifecycle operations require elevated privileges, and the integration smoke test is root-gated. A future packaging pass can narrow this to the exact capability set.

Start the daemon with an explicit `run` subcommand:

```bash
sudo ./nie run --config ./config.yaml
```

## Commands

- `make generate`: regenerate eBPF bindings with `go generate ./internal/ebpf`
- `make test`: run the unit test suite with `go test ./...`
- `make build`: build the daemon with `go build ./cmd/nie`
- `go run ./cmd/nie --help`: show CLI help
- `sudo go run ./cmd/nie run --config ./config.yaml`: start the daemon with a config file
- `make test-integration`: run the root-gated smoke test with `sudo -E go test -tags=integration ./test/...`
- `make vm-test`: boot or reprovision the Vagrant VM and run the mounted repo validation flow inside the guest

## Releases

Releases are cut automatically from `main`.

- `fix:` -> patch
- `feat:` -> minor
- `BREAKING CHANGE:` or `type!:` -> major
- artifacts are published for Linux `amd64` and `arm64` with GoReleaser

- project name is `nie`
- build target is `./cmd/nie`
- builds are Linux-only (`amd64`, `arm64`)
- archives are `tar.gz` with stable names:
  `nie_linux_x86_64.tar.gz` and `nie_linux_arm64.tar.gz`
- each archive includes `README.md` and `config.yaml`
- checksum output is `checksums.txt`
- release notes ownership stays with semantic-release via
  `release.mode: keep-existing`
- existing release artifacts may be replaced via
  `replace_existing_artifacts: true`

## VM Validation

The repository includes a Vagrant workflow under `vm/vagrant` for validating `nie`
inside a clean Ubuntu guest with the `virtualbox` provider. The guest mounts the
current repository and runs tests directly from that synced working tree.

`make vm-test` now exercises the real guest datapath on a non-loopback interface.
The host runner starts a small fixture service on the Vagrant private network, and
the guest VM reaches that fixture over its routed private-network path instead of
loopback.

The VM suite covers:

- default-deny before DNS learning for real egress to the host-side fixture
- allow-after-learning once an allowed hostname resolves to the same fixture IPv4
- denied hostnames returning `REFUSED` in `enforce`
- `audit` logging for both `would_deny_dns` and `would_deny_egress`
- one long-lived guest process losing host-wide DNS and TCP access while `nie` is active
- that same process recovering after `nie` shuts down, then repeating the restart/recovery cycle cleanly

Host prerequisites:

- `vagrant`
- `VirtualBox`

Useful commands:

- `make vm-test`
- `cd vm/vagrant && vagrant ssh`
- `cd vm/vagrant && vagrant destroy -f`
