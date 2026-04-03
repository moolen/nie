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
