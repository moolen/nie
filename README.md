# nie

Bootstrap scaffold for the `github.com/moolen/nie` module.

`config.yaml` is expected to contain:

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
```
