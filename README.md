# nie

`nie` is a single-host Linux egress policy agent. It follows the same basic model as Cilium's DNS proxy path: intercept DNS, evaluate the queried hostname against an allow policy, forward the request upstream, learn trusted IPv4 destinations from A answers, and let a tc egress program enforce default-deny for unknown destinations.

## Scope

- single host
- single interface
- IPv4 only in v1
- classic DNS over UDP/TCP port 53 only
- learns A records only; AAAA answers are ignored

## Current Status

`cmd/nie` now wires the full native runtime lifecycle:

- an eBPF manager that prepares bpffs, loads/pins runtime objects, and attaches the tc egress classifier
- a redirect manager that installs DNS interception rules with native nftables APIs
- a DNS proxy that forwards queries, enforces policy, and writes trusted A-record destinations into the live eBPF allow map

The daemon does not use shell-out `iptables`/`tc` orchestration for normal startup. True `iptables-legacy`-only hosts are explicitly unsupported.

## Configuration

`config.yaml` uses explicit `host:port` DNS listener addresses, a single interface, and glob-based hostname policy:

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
    - "**.githubusercontent.com"
```

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
6. A-record answers from upstream are converted into trusted IPv4 entries for the eBPF allow map.
7. The tc egress program uses `dns.mark` as a bypass mark for proxy-originated DNS traffic.

## Runtime Lifecycle

- eBPF startup ensures `/sys/fs/bpf` exists and mounts `bpffs` when needed, then prepares `/sys/fs/bpf/nie`, loads objects, configures mode/mark, pins maps, and attaches tc egress on the configured interface.
- Redirect startup detects nftables availability and installs only `nie`-owned DNS redirect rules.
- On shutdown, `nie` stops DNS first, then removes redirect rules/chains/tables it owns, detaches tc egress, closes objects, removes pinned state under `/sys/fs/bpf/nie`, and removes clsact when it created it.
- If conflicting preexisting `nie` redirect objects are present, startup/shutdown surfaces explicit errors instead of mutating unknown state.

## Modes

- `enforce`: default deny. Unknown or untrusted egress should be dropped, and denied DNS queries are refused locally.
- `audit`: allow traffic but emit `would_deny_dns` and `would_deny_egress` logs for flows that would have been blocked.

## Privileges

Run `nie` as root for now. Native nftables and tc/BPF lifecycle operations require elevated privileges, and the integration smoke test is root-gated. A future packaging pass can narrow this to the exact capability set.

## Commands

- `make generate`: regenerate eBPF bindings with `go generate ./internal/ebpf`
- `make test`: run the unit test suite with `go test ./...`
- `make build`: build the daemon with `go build ./cmd/nie`
- `make test-integration`: run the root-gated smoke test with `sudo -E go test -tags=integration ./test/...`
- `make vm-test`: boot or reprovision the Vagrant VM and run the mounted repo validation flow inside the guest

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
