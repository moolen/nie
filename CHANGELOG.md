## [1.2.1](https://github.com/moolen/nie/compare/v1.2.0...v1.2.1) (2026-04-05)


### Bug Fixes

* make smoke ci loopback ipv4 only ([d4d91d1](https://github.com/moolen/nie/commit/d4d91d1287e7a554ad65fd5b47fd4ce2c897ba57))

# [1.2.0](https://github.com/moolen/nie/compare/v1.1.0...v1.2.0) (2026-04-05)


### Bug Fixes

* avoid stale trust refresh races ([78b6828](https://github.com/moolen/nie/commit/78b6828c0acfd03c641816718becb7b55416bd3a))
* clamp retained trust refresh ttl ([e6c050c](https://github.com/moolen/nie/commit/e6c050cb30a052ba6e306fdd4a2331ec056ee207))
* keep retained trust entries alive in datapath ([32a8864](https://github.com/moolen/nie/commit/32a8864a69ea93b16751c15284dba18c870dbb64))
* only refresh retained stale trust entries ([4f11a11](https://github.com/moolen/nie/commit/4f11a11d62ade62295eeb7c728edf9379b71c023))
* qualify trust duration parse errors ([8a62814](https://github.com/moolen/nie/commit/8a62814c6e413b855d491ded67062dbd725648a8))


### Features

* add trust cleanup config ([fca8ccf](https://github.com/moolen/nie/commit/fca8ccfb9228055072897a935a52a5a63c1e562c))
* wire trust cleanup config into runtime ([e7146e4](https://github.com/moolen/nie/commit/e7146e451722a477925e05509753b162c9c5eec8))

# [1.1.0](https://github.com/moolen/nie/compare/v1.0.4...v1.1.0) (2026-04-05)


### Bug Fixes

* complete stale trust cleanup wiring ([e796e2b](https://github.com/moolen/nie/commit/e796e2b7c4a7c7f2760eaaa93dc1817315d15af6))
* keep stale tcp entries on conntrack errors ([c4cf380](https://github.com/moolen/nie/commit/c4cf3806604ec271c29cc10458e5a6f85eba3447))
* keep trustsync stale pruning explicit ([d164088](https://github.com/moolen/nie/commit/d164088a1509ca8eac0ed052c6b0a39d40e24238))
* preserve trust writer compatibility for delete support ([1b993c2](https://github.com/moolen/nie/commit/1b993c2c704d8971f6f62e2b24ec51e26702c499))
* remove dns proxy trust writer fallback ([f0314b1](https://github.com/moolen/nie/commit/f0314b151bf8ac27ee4a8bd8ccfb0388c8350a27))


### Features

* add dns trust reconciliation state ([1882708](https://github.com/moolen/nie/commit/188270875761b354a84448f418a92bfc51674e6f))
* add ebpf trust delete support ([062b464](https://github.com/moolen/nie/commit/062b464ceb580a76aa3ddaa9ebb69d8e4939af16))
* gate stale tcp cleanup on conntrack ([89c27de](https://github.com/moolen/nie/commit/89c27defb16db9eb78a30fc47b653d1179b94ed7))
* reconcile dns trust by hostname ([30f0646](https://github.com/moolen/nie/commit/30f0646fa38964699690da90e2abb4f665df7fe3))
* reconcile long-lived dns trust state ([9237394](https://github.com/moolen/nie/commit/9237394fbfff8b4794f54df2d59171aef1839ef2))
* run trust reconciler in app lifecycle ([618c516](https://github.com/moolen/nie/commit/618c51666bee2f7cf9e3828c50cb09530728458e))

## [1.0.4](https://github.com/moolen/nie/compare/v1.0.3...v1.0.4) (2026-04-05)


### Bug Fixes

* harden learned trust and MITM classification ([2a859eb](https://github.com/moolen/nie/commit/2a859eb4ed42df335c9e8218c8df89b319f49e11))

## [1.0.3](https://github.com/moolen/nie/compare/v1.0.2...v1.0.3) (2026-04-05)


### Bug Fixes

* harden mitm authority and ipv6 startup checks ([e1ef299](https://github.com/moolen/nie/commit/e1ef29960e16ac87ce28818eda62bdcfbad099cb))

## [1.0.2](https://github.com/moolen/nie/compare/v1.0.1...v1.0.2) (2026-04-05)


### Bug Fixes

* **ci:** clean npm workspace before goreleaser publish ([757122f](https://github.com/moolen/nie/commit/757122f1ea18742490fe70677bb736686ddd8898))

## [1.0.1](https://github.com/moolen/nie/compare/v1.0.0...v1.0.1) (2026-04-05)


### Bug Fixes

* **ci:** publish goreleaser assets from release workflow ([0531cd0](https://github.com/moolen/nie/commit/0531cd0dd4d2f463256d092c750ac556a939564d))

# 1.0.0 (2026-04-05)


### Bug Fixes

* allow expiry equal now in egress and writer ([e6298d0](https://github.com/moolen/nie/commit/e6298d0821dcb072ae216782a14d4f73303996dd))
* correct tc key encoding and monotonic expiry ([19095f2](https://github.com/moolen/nie/commit/19095f2b229b55bc8a5ce2791b067197319e2f54))
* enforce https validation contract ([76dc814](https://github.com/moolen/nie/commit/76dc814e82540a0f01c9e1bdcdad0d7baa5fde58))
* enforce strict YAML config decoding and trim fields ([4c699ee](https://github.com/moolen/nie/commit/4c699ee9d53b85119f43075f68efd71893fd5413))
* harden dns proxy request handling ([ed329fa](https://github.com/moolen/nie/commit/ed329fa710b7faf66a44b5479c37d3ddeeae1539))
* harden fragment parsing and trust-plan no-match coverage ([0b9ac08](https://github.com/moolen/nie/commit/0b9ac08e8cb66c9f7927f2b2f99770097f83a42f))
* harden http policy rule validation and path wildcard semantics ([3f8d2b0](https://github.com/moolen/nie/commit/3f8d2b0cd6b3481c839e66c1dcc6a9f64e0f3322))
* harden https mitm proxy handling ([13ac255](https://github.com/moolen/nie/commit/13ac2554f4aa49a364a543c40d2154b4a4b2da3b))
* harden mitm ca loading and leaf issuance ([cc2c223](https://github.com/moolen/nie/commit/cc2c223119876f960f83c9049865049987c40d78))
* include config entry indexes in validation errors ([3824700](https://github.com/moolen/nie/commit/382470033441685595c88a019ffc61e8eaefb44d))
* link vm multiarch asm headers ([dbc5204](https://github.com/moolen/nie/commit/dbc520446152a8d2a18632f22d9823fe36072250))
* normalize mode/default and map empty config error ([66df753](https://github.com/moolen/nie/commit/66df753b5bb424fc2e65436d8f128127d0679225))
* **policy:** align invalid pattern error context ([491c33e](https://github.com/moolen/nie/commit/491c33edc78a9f6119632ab451d778ae63818ea7))
* reject leaf issuance when ca is not yet valid ([89cf97e](https://github.com/moolen/nie/commit/89cf97e8714e64a5e306208255c0fa7207eda89c))
* restore missing tracked runtime files ([7a8bbcf](https://github.com/moolen/nie/commit/7a8bbcf7f2904403fdd0b7a9a37301509bedcab2))
* reuse one upstream h2 connection ([8e552df](https://github.com/moolen/nie/commit/8e552df047af9aa29ae952f7b9a77296ed0eb735))
* rollback start failures and surface dns bind errors ([47de178](https://github.com/moolen/nie/commit/47de178c9478c8e39b720e1b8ef20aff27479965))
* run ci package tests with sudo ([a01819f](https://github.com/moolen/nie/commit/a01819f7da5ae1e339ed4e3aea4d09e574cb5b28))
* stop all runtime components on shutdown ([dcaccad](https://github.com/moolen/nie/commit/dcaccad9a5087a0637af18bc3f139dce285c6409))
* stop dns listeners best effort ([7ade7a2](https://github.com/moolen/nie/commit/7ade7a25354555a775d21831b483951ee4d0b8b7))
* support wildcard mitm trust patterns ([8f1ffb5](https://github.com/moolen/nie/commit/8f1ffb50bbcaf4b43553a5fab82fa04a4de77988))
* tighten config validation for upstream entries ([d59bf92](https://github.com/moolen/nie/commit/d59bf92cb0c3da807cbea2700b2daebf5ef4c166))
* tighten dns proxy request path ([95c3534](https://github.com/moolen/nie/commit/95c35345277f478de529a5fc7becc0920f41fe81))
* tighten hostname policy validation and tests ([2709d00](https://github.com/moolen/nie/commit/2709d0094a5c298a8682293f97141878695425a8))
* validate trust entry expiry before writing ([6237bca](https://github.com/moolen/nie/commit/6237bca44d519cd269b3105313377878f787444e))


### Features

* add config loading and validation ([ea88f52](https://github.com/moolen/nie/commit/ea88f52bdfd62b69274f00c563359bc532bc1e4a))
* add dns proxy decision path ([958be9e](https://github.com/moolen/nie/commit/958be9ef380e593ed44711a46c9d81e79972c3f3))
* add dns redirect rule manager ([c355b30](https://github.com/moolen/nie/commit/c355b30b6110f5b1c082e4d90957c8c62dce4e6e))
* add ebpf loader and pinned map api ([f25e05c](https://github.com/moolen/nie/commit/f25e05c5223f990f38457bf339b2e677f84bda35))
* add explicit hostname wildcard semantics ([49fd2f8](https://github.com/moolen/nie/commit/49fd2f8f0d1990f0121ff403a39abc0a156545f5))
* add hostname policy engine ([bc1841c](https://github.com/moolen/nie/commit/bc1841ca7a06b9c01a132ea952ffdfba1a8bded7))
* add http mitm policy engine ([466e89e](https://github.com/moolen/nie/commit/466e89ee4ce5f98b855aeba1bfe110f66d02b440))
* add http2 mitm coverage and ci smoke test ([e30c1c1](https://github.com/moolen/nie/commit/e30c1c19e96156144edea5eeed6bbbe295ca8b31))
* add https config and dns trust planning ([9fbf413](https://github.com/moolen/nie/commit/9fbf413f1e2c35c1f642afea10c546f25bddb01f))
* add mitm certificate authority management ([64541b7](https://github.com/moolen/nie/commit/64541b793d5d1913d1457fda1e9a5d1024cb5e2f))
* add tc egress enforcement program ([801a954](https://github.com/moolen/nie/commit/801a954703de7a2a062925ea86e85ba6800a5df5))
* add transparent https redirect classification ([780842c](https://github.com/moolen/nie/commit/780842c80ff16c256fbe990e9aaa14027d6e41a3))
* add trust entry types and ttl handling ([f9b7303](https://github.com/moolen/nie/commit/f9b7303dee473e6c4ce5d80b8af4d70cb9891489))
* log audit egress events for vm coverage ([fe4cc4e](https://github.com/moolen/nie/commit/fe4cc4ec044c0f55f9470123b2652fac099f88e9))
* make dns trust entries port aware ([cff98a6](https://github.com/moolen/nie/commit/cff98a613db44322131c09d5754757694550efe9))
* use tc allow map key/value structs ([8fa6560](https://github.com/moolen/nie/commit/8fa65600785d7b72e93ce80d15c9f2b41bdcd121))
* validate dns host and port endpoints ([3bffb9c](https://github.com/moolen/nie/commit/3bffb9cdf241fb2bb0f2c7348831fe9e2ebf4a43))
* validate dns mark in config ([d5d8891](https://github.com/moolen/nie/commit/d5d8891bf0f6d21f9948516198fc3a46350b1a7c))
* wire runtime service and cli ([0512d57](https://github.com/moolen/nie/commit/0512d572bfce94cfdb4f1f4ca27b4554f8b433cf))
* wire transparent https mitm runtime ([4247827](https://github.com/moolen/nie/commit/42478279a059f3550ff83537eb847743368c3fc8))
