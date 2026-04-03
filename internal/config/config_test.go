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
