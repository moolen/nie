package config

import "testing"

func TestLoadConfig_Valid(t *testing.T) {
	raw := []byte(`
mode: audit
interface: eth0
dns:
  listen: 127.0.0.1:1053
  upstreams: [1.1.1.1:53]
  mark: 4242
policy:
  default: deny
  allow: ["*.github.com", "github.com"]
`)

	cfg, err := Load(raw)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Mode != ModeAudit {
		t.Fatalf("Mode = %q, want %q", cfg.Mode, ModeAudit)
	}
}

func TestLoadConfig_RejectsMissingInterface(t *testing.T) {
	_, err := Load([]byte(`mode: enforce`))
	if err == nil {
		t.Fatal("Load() error = nil, want validation error")
	}
}

func TestLoadConfig_DefaultsPolicyAllowToEmptySlice(t *testing.T) {
	raw := []byte(`
mode: enforce
interface: eth0
dns:
  listen: 127.0.0.1:1053
  upstreams: [1.1.1.1:53]
  mark: 4242
policy:
  default: deny
`)

	cfg, err := Load(raw)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Policy.Allow == nil {
		t.Fatal("Policy.Allow = nil, want non-nil empty slice")
	}
	if len(cfg.Policy.Allow) != 0 {
		t.Fatalf("len(Policy.Allow) = %d, want 0", len(cfg.Policy.Allow))
	}
}

func TestLoadConfig_RejectsEmptyOrWhitespaceUpstreamEntries(t *testing.T) {
	tests := []struct {
		name      string
		upstreams string
	}{
		{name: "empty", upstreams: `[""]`},
		{name: "whitespace", upstreams: `["   "]`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := []byte(`
mode: enforce
interface: eth0
dns:
  listen: 127.0.0.1:1053
  upstreams: ` + tt.upstreams + `
  mark: 4242
policy:
  default: deny
  allow: []
`)

			_, err := Load(raw)
			if err == nil {
				t.Fatal("Load() error = nil, want validation error")
			}
		})
	}
}

func TestLoadConfig_RejectsUnknownYAMLKeys(t *testing.T) {
	raw := []byte(`
mode: enforce
interface: eth0
unknown: true
dns:
  listen: 127.0.0.1:1053
  upstreams: [1.1.1.1:53]
  mark: 4242
policy:
  default: deny
  allow: ["github.com"]
`)

	_, err := Load(raw)
	if err == nil {
		t.Fatal("Load() error = nil, want unknown field error")
	}
}

func TestLoadConfig_TrimsStringFields(t *testing.T) {
	raw := []byte(`
mode: enforce
interface: "  eth0  "
dns:
  listen: " 127.0.0.1:1053  "
  upstreams: [" 1.1.1.1:53  ", " 9.9.9.9:53 "]
  mark: 4242
policy:
  default: deny
  allow: [" *.github.com ", " github.com "]
`)

	cfg, err := Load(raw)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Interface != "eth0" {
		t.Fatalf("Interface = %q, want %q", cfg.Interface, "eth0")
	}
	if cfg.DNS.Listen != "127.0.0.1:1053" {
		t.Fatalf("DNS.Listen = %q, want %q", cfg.DNS.Listen, "127.0.0.1:1053")
	}
	if cfg.DNS.Upstreams[0] != "1.1.1.1:53" || cfg.DNS.Upstreams[1] != "9.9.9.9:53" {
		t.Fatalf("DNS.Upstreams = %#v, want trimmed entries", cfg.DNS.Upstreams)
	}
	if cfg.Policy.Allow[0] != "*.github.com" || cfg.Policy.Allow[1] != "github.com" {
		t.Fatalf("Policy.Allow = %#v, want trimmed entries", cfg.Policy.Allow)
	}
}

func TestLoadConfig_RejectsWhitespaceOnlyStringFields(t *testing.T) {
	tests := []struct {
		name   string
		config string
	}{
		{
			name: "interface",
			config: `
mode: enforce
interface: "   "
dns:
  listen: 127.0.0.1:1053
  upstreams: [1.1.1.1:53]
  mark: 4242
policy:
  default: deny
  allow: ["github.com"]
`,
		},
		{
			name: "dns.listen",
			config: `
mode: enforce
interface: eth0
dns:
  listen: "   "
  upstreams: [1.1.1.1:53]
  mark: 4242
policy:
  default: deny
  allow: ["github.com"]
`,
		},
		{
			name: "dns.upstreams entry",
			config: `
mode: enforce
interface: eth0
dns:
  listen: 127.0.0.1:1053
  upstreams: [1.1.1.1:53, "   "]
  mark: 4242
policy:
  default: deny
  allow: ["github.com"]
`,
		},
		{
			name: "policy.allow entry",
			config: `
mode: enforce
interface: eth0
dns:
  listen: 127.0.0.1:1053
  upstreams: [1.1.1.1:53]
  mark: 4242
policy:
  default: deny
  allow: ["github.com", "   "]
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load([]byte(tt.config))
			if err == nil {
				t.Fatal("Load() error = nil, want validation error")
			}
		})
	}
}
