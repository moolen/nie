package config

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestLoadConfig_InterfaceSelectorExplicit(t *testing.T) {
	raw := []byte(`
mode: enforce
interface:
  mode: explicit
  name: eth0
dns:
  listen: 127.0.0.1:1053
  upstreams:
    mode: explicit
    addresses: [1.1.1.1:53]
  mark: 4242
policy:
  default: deny
  allow: ["github.com"]
https:
  ports: [443]
`)

	cfg, err := Load(raw)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Interface.Mode != "explicit" {
		t.Fatalf("Interface.Mode = %q, want %q", cfg.Interface.Mode, "explicit")
	}
	if cfg.Interface.Name != "eth0" {
		t.Fatalf("Interface.Name = %q, want %q", cfg.Interface.Name, "eth0")
	}
}

func TestLoadConfig_InterfaceSelectorAuto(t *testing.T) {
	raw := []byte(`
mode: enforce
interface:
  mode: auto
dns:
  listen: 127.0.0.1:1053
  upstreams:
    mode: explicit
    addresses: [1.1.1.1:53]
  mark: 4242
policy:
  default: deny
  allow: ["github.com"]
https:
  ports: [443]
`)

	cfg, err := Load(raw)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Interface.Mode != "auto" {
		t.Fatalf("Interface.Mode = %q, want %q", cfg.Interface.Mode, "auto")
	}
	if cfg.Interface.Name != "" {
		t.Fatalf("Interface.Name = %q, want empty", cfg.Interface.Name)
	}
}

func TestLoadConfig_DNSUpstreamsSelectorExplicit(t *testing.T) {
	raw := []byte(`
mode: enforce
interface:
  mode: explicit
  name: eth0
dns:
  listen: 127.0.0.1:1053
  upstreams:
    mode: explicit
    addresses: [" 1.1.1.1:53 ", " 9.9.9.9:53 "]
  mark: 4242
policy:
  default: deny
  allow: ["github.com"]
https:
  ports: [443]
`)

	cfg, err := Load(raw)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.DNS.Upstreams.Mode != "explicit" {
		t.Fatalf("DNS.Upstreams.Mode = %q, want %q", cfg.DNS.Upstreams.Mode, "explicit")
	}
	if got, want := cfg.DNS.Upstreams.Addresses, []string{"1.1.1.1:53", "9.9.9.9:53"}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("DNS.Upstreams.Addresses = %#v, want %#v", got, want)
	}
}

func TestLoadConfig_DNSUpstreamsSelectorAuto(t *testing.T) {
	raw := []byte(`
mode: enforce
interface:
  mode: explicit
  name: eth0
dns:
  listen: 127.0.0.1:1053
  upstreams:
    mode: auto
  mark: 4242
policy:
  default: deny
  allow: ["github.com"]
https:
  ports: [443]
`)

	cfg, err := Load(raw)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.DNS.Upstreams.Mode != "auto" {
		t.Fatalf("DNS.Upstreams.Mode = %q, want %q", cfg.DNS.Upstreams.Mode, "auto")
	}
	if len(cfg.DNS.Upstreams.Addresses) != 0 {
		t.Fatalf("DNS.Upstreams.Addresses = %#v, want empty", cfg.DNS.Upstreams.Addresses)
	}
}

func TestLoadConfig_RejectsInterfaceSelectorWithoutMode(t *testing.T) {
	_, err := Load([]byte(`
mode: enforce
interface:
  name: eth0
dns:
  listen: 127.0.0.1:1053
  upstreams:
    mode: explicit
    addresses: [1.1.1.1:53]
  mark: 4242
policy:
  default: deny
  allow: ["github.com"]
https:
  ports: [443]
`))
	if err == nil {
		t.Fatal("Load() error = nil, want validation error")
	}
	if !strings.Contains(err.Error(), "interface.mode") {
		t.Fatalf("Load() error = %v, want interface.mode context", err)
	}
}

func TestLoadConfig_RejectsExplicitInterfaceWithoutName(t *testing.T) {
	_, err := Load([]byte(`
mode: enforce
interface:
  mode: explicit
dns:
  listen: 127.0.0.1:1053
  upstreams:
    mode: explicit
    addresses: [1.1.1.1:53]
  mark: 4242
policy:
  default: deny
  allow: ["github.com"]
https:
  ports: [443]
`))
	if err == nil {
		t.Fatal("Load() error = nil, want validation error")
	}
	if !strings.Contains(err.Error(), "interface.name") {
		t.Fatalf("Load() error = %v, want interface.name context", err)
	}
}

func TestLoadConfig_RejectsAutoInterfaceWithName(t *testing.T) {
	_, err := Load([]byte(`
mode: enforce
interface:
  mode: auto
  name: eth0
dns:
  listen: 127.0.0.1:1053
  upstreams:
    mode: explicit
    addresses: [1.1.1.1:53]
  mark: 4242
policy:
  default: deny
  allow: ["github.com"]
https:
  ports: [443]
`))
	if err == nil {
		t.Fatal("Load() error = nil, want validation error")
	}
	if !strings.Contains(err.Error(), "interface.name") {
		t.Fatalf("Load() error = %v, want interface.name context", err)
	}
}

func TestLoadConfig_RejectsExplicitDNSUpstreamsWithoutAddresses(t *testing.T) {
	_, err := Load([]byte(`
mode: enforce
interface:
  mode: explicit
  name: eth0
dns:
  listen: 127.0.0.1:1053
  upstreams:
    mode: explicit
  mark: 4242
policy:
  default: deny
  allow: ["github.com"]
https:
  ports: [443]
`))
	if err == nil {
		t.Fatal("Load() error = nil, want validation error")
	}
	if !strings.Contains(err.Error(), "dns.upstreams.addresses") {
		t.Fatalf("Load() error = %v, want dns.upstreams.addresses context", err)
	}
}

func TestLoadConfig_RejectsAutoDNSUpstreamsWithAddresses(t *testing.T) {
	_, err := Load([]byte(`
mode: enforce
interface:
  mode: explicit
  name: eth0
dns:
  listen: 127.0.0.1:1053
  upstreams:
    mode: auto
    addresses: [1.1.1.1:53]
  mark: 4242
policy:
  default: deny
  allow: ["github.com"]
https:
  ports: [443]
`))
	if err == nil {
		t.Fatal("Load() error = nil, want validation error")
	}
	if !strings.Contains(err.Error(), "dns.upstreams.addresses") {
		t.Fatalf("Load() error = %v, want dns.upstreams.addresses context", err)
	}
}

func TestLoadConfig_Valid(t *testing.T) {
	raw := []byte(`
mode: audit
interface:
  mode: explicit
  name: eth0
dns:
  listen: 127.0.0.1:1053
  upstreams:
    mode: explicit
    addresses: [1.1.1.1:53]
  mark: 4242
policy:
  default: deny
  allow: ["*.github.com", "github.com"]
https:
  ports: [443]
`)

	cfg, err := Load(raw)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Mode != ModeAudit {
		t.Fatalf("Mode = %q, want %q", cfg.Mode, ModeAudit)
	}
}

func TestLoadConfig_HTTPSDefaults(t *testing.T) {
	raw := []byte(`
mode: enforce
interface:
  mode: explicit
  name: eth0
dns:
  listen: 127.0.0.1:1053
  upstreams:
    mode: explicit
    addresses: [1.1.1.1:53]
  mark: 4242
policy:
  default: deny
  allow: ["github.com"]
https:
  ports: [443]
  mitm:
    rules:
      - host: api.github.com
        port: 443
        methods: ["GET"]
        paths: ["/repos/**"]
        action: allow
`)

	cfg, err := Load(raw)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.HTTPS.Listen != "127.0.0.1:9443" {
		t.Fatalf("HTTPS.Listen = %q, want default 127.0.0.1:9443", cfg.HTTPS.Listen)
	}
	if cfg.HTTPS.SNI.Missing != "deny" {
		t.Fatalf("HTTPS.SNI.Missing = %q, want deny", cfg.HTTPS.SNI.Missing)
	}
}

func baseConfigWithHTTPS(httpsBlock string) []byte {
	return []byte(`
mode: enforce
interface:
  mode: explicit
  name: eth0
dns:
  listen: 127.0.0.1:1053
  upstreams:
    mode: explicit
    addresses: [1.1.1.1:53]
  mark: 4242
policy:
  default: deny
  allow: ["github.com"]
https:
` + httpsBlock + `
`)
}

func TestLoadConfig_AllowsMissingHTTPSBlock(t *testing.T) {
	cfg, err := Load([]byte(`
mode: enforce
interface:
  mode: explicit
  name: eth0
dns:
  listen: 127.0.0.1:1053
  upstreams:
    mode: explicit
    addresses: [1.1.1.1:53]
  mark: 4242
policy:
  default: deny
  allow: ["github.com"]
`))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.HTTPS.Configured() {
		t.Fatal("HTTPS.Configured() = true, want false when https block is omitted")
	}
}

func TestLoadConfig_RejectsEmptyHTTPSBlock(t *testing.T) {
	_, err := Load([]byte(`
mode: enforce
interface:
  mode: explicit
  name: eth0
dns:
  listen: 127.0.0.1:1053
  upstreams:
    mode: explicit
    addresses: [1.1.1.1:53]
  mark: 4242
policy:
  default: deny
  allow: ["github.com"]
https: {}
`))
	if err == nil {
		t.Fatal("Load() error = nil, want validation error")
	}
	if !strings.Contains(err.Error(), "https.ports") {
		t.Fatalf("Load() error = %v, want https.ports validation", err)
	}
}

func TestLoadConfig_RejectsInvalidHTTPSListen(t *testing.T) {
	_, err := Load(baseConfigWithHTTPS(`
  listen: 127.0.0.1
  ports: [443]
`))
	if err == nil {
		t.Fatal("Load() error = nil, want validation error")
	}
	if !strings.Contains(err.Error(), "https.listen") {
		t.Fatalf("Load() error = %v, want https.listen context", err)
	}
}

func TestLoadConfig_RejectsDuplicateHTTPSPorts(t *testing.T) {
	_, err := Load(baseConfigWithHTTPS(`
  ports: [443, 443]
`))
	if err == nil {
		t.Fatal("Load() error = nil, want validation error")
	}
	if !strings.Contains(err.Error(), "duplicates port") {
		t.Fatalf("Load() error = %v, want duplicate-port reason", err)
	}
}

func TestLoadConfig_RejectsOutOfRangeHTTPSPorts(t *testing.T) {
	_, err := Load(baseConfigWithHTTPS(`
  ports: [0]
`))
	if err == nil {
		t.Fatal("Load() error = nil, want validation error")
	}
	if !strings.Contains(err.Error(), "1-65535") {
		t.Fatalf("Load() error = %v, want out-of-range reason", err)
	}
}

func TestLoadConfig_RejectsInvalidHTTPSSNIMissing(t *testing.T) {
	_, err := Load(baseConfigWithHTTPS(`
  ports: [443]
  sni:
    missing: allow
`))
	if err == nil {
		t.Fatal("Load() error = nil, want validation error")
	}
	if !strings.Contains(err.Error(), "https.sni.missing") {
		t.Fatalf("Load() error = %v, want https.sni.missing context", err)
	}
}

func TestLoadConfig_RejectsInvalidHTTPSMITMDefault(t *testing.T) {
	_, err := Load(baseConfigWithHTTPS(`
  ports: [443]
  mitm:
    default: allow
`))
	if err == nil {
		t.Fatal("Load() error = nil, want validation error")
	}
	if !strings.Contains(err.Error(), "https.mitm.default") {
		t.Fatalf("Load() error = %v, want https.mitm.default context", err)
	}
}

func TestLoadConfig_RejectsInvalidHTTPSMITMRuleFields(t *testing.T) {
	tests := []struct {
		name        string
		rule        string
		wantContext string
	}{
		{
			name: "empty host",
			rule: `
      - host: "   "
        port: 443
        methods: ["GET"]
        paths: ["/"]
        action: allow`,
			wantContext: "https.mitm.rules[0].host",
		},
		{
			name: "bad port",
			rule: `
      - host: api.github.com
        port: 0
        methods: ["GET"]
        paths: ["/"]
        action: allow`,
			wantContext: "https.mitm.rules[0].port",
		},
		{
			name: "empty methods",
			rule: `
      - host: api.github.com
        port: 443
        methods: []
        paths: ["/"]
        action: allow`,
			wantContext: "https.mitm.rules[0].methods",
		},
		{
			name: "empty paths",
			rule: `
      - host: api.github.com
        port: 443
        methods: ["GET"]
        paths: []
        action: allow`,
			wantContext: "https.mitm.rules[0].paths",
		},
		{
			name: "invalid action",
			rule: `
      - host: api.github.com
        port: 443
        methods: ["GET"]
        paths: ["/"]
        action: block`,
			wantContext: "https.mitm.rules[0].action",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(baseConfigWithHTTPS(`
  ports: [443]
  mitm:
    rules:` + tt.rule + `
`))
			if err == nil {
				t.Fatal("Load() error = nil, want validation error")
			}
			if !strings.Contains(err.Error(), tt.wantContext) {
				t.Fatalf("Load() error = %v, want %q context", err, tt.wantContext)
			}
		})
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
interface:
  mode: explicit
  name: eth0
dns:
  listen: 127.0.0.1:1053
  upstreams:
    mode: explicit
    addresses: [1.1.1.1:53]
  mark: 4242
policy:
  default: deny
https:
  ports: [443]
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
interface:
  mode: explicit
  name: eth0
dns:
  listen: 127.0.0.1:1053
  upstreams:
    mode: explicit
    addresses: ` + tt.upstreams + `
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
interface:
  mode: explicit
  name: eth0
unknown: true
dns:
  listen: 127.0.0.1:1053
  upstreams:
    mode: explicit
    addresses: [1.1.1.1:53]
  mark: 4242
policy:
  default: deny
  allow: ["github.com"]
`)

	_, err := Load(raw)
	if err == nil {
		t.Fatal("Load() error = nil, want unknown field error")
	}
	if !strings.Contains(err.Error(), "field unknown not found") {
		t.Fatalf("Load() error = %v, want unknown-field reason", err)
	}
}

func TestLoadConfig_TrimsStringFields(t *testing.T) {
	raw := []byte(`
mode: enforce
interface:
  mode: explicit
  name: "  eth0  "
dns:
  listen: " 127.0.0.1:1053  "
  upstreams:
    mode: explicit
    addresses: [" 1.1.1.1:53  ", " 9.9.9.9:53 "]
  mark: 4242
policy:
  default: deny
  allow: [" *.github.com ", " github.com "]
https:
  ports: [443]
`)

	cfg, err := Load(raw)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Interface.Name != "eth0" {
		t.Fatalf("Interface.Name = %q, want %q", cfg.Interface.Name, "eth0")
	}
	if cfg.DNS.Listen != "127.0.0.1:1053" {
		t.Fatalf("DNS.Listen = %q, want %q", cfg.DNS.Listen, "127.0.0.1:1053")
	}
	if cfg.DNS.Upstreams.Addresses[0] != "1.1.1.1:53" || cfg.DNS.Upstreams.Addresses[1] != "9.9.9.9:53" {
		t.Fatalf("DNS.Upstreams.Addresses = %#v, want trimmed entries", cfg.DNS.Upstreams.Addresses)
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
interface:
  mode: explicit
  name: "   "
dns:
  listen: 127.0.0.1:1053
  upstreams:
    mode: explicit
    addresses: [1.1.1.1:53]
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
interface:
  mode: explicit
  name: eth0
dns:
  listen: "   "
  upstreams:
    mode: explicit
    addresses: [1.1.1.1:53]
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
interface:
  mode: explicit
  name: eth0
dns:
  listen: 127.0.0.1:1053
  upstreams:
    mode: explicit
    addresses: [1.1.1.1:53, "   "]
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
interface:
  mode: explicit
  name: eth0
dns:
  listen: 127.0.0.1:1053
  upstreams:
    mode: explicit
    addresses: [1.1.1.1:53]
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

func TestLoadConfig_RejectsInvalidMode(t *testing.T) {
	_, err := Load([]byte(`
mode: monitor
interface:
  mode: explicit
  name: eth0
dns:
  listen: 127.0.0.1:1053
  upstreams:
    mode: explicit
    addresses: [1.1.1.1:53]
  mark: 4242
policy:
  default: deny
  allow: ["github.com"]
https:
  ports: [443]
`))
	if err == nil {
		t.Fatal("Load() error = nil, want validation error")
	}
}

func TestLoadConfig_RejectsMissingDNSListen(t *testing.T) {
	_, err := Load([]byte(`
mode: enforce
interface:
  mode: explicit
  name: eth0
dns:
  upstreams:
    mode: explicit
    addresses: [1.1.1.1:53]
  mark: 4242
policy:
  default: deny
  allow: ["github.com"]
`))
	if err == nil {
		t.Fatal("Load() error = nil, want validation error")
	}
}

func TestLoadConfig_RejectsMissingOrEmptyDNSUpstreams(t *testing.T) {
	tests := []struct {
		name   string
		config string
	}{
		{
			name: "missing",
			config: `
mode: enforce
interface:
  mode: explicit
  name: eth0
dns:
  listen: 127.0.0.1:1053
  mark: 4242
policy:
  default: deny
  allow: ["github.com"]
`,
		},
		{
			name: "empty",
			config: `
mode: enforce
interface:
  mode: explicit
  name: eth0
dns:
  listen: 127.0.0.1:1053
  upstreams: []
  mark: 4242
policy:
  default: deny
  allow: ["github.com"]
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

func TestLoadConfig_RejectsInvalidPolicyDefault(t *testing.T) {
	_, err := Load([]byte(`
mode: enforce
interface:
  mode: explicit
  name: eth0
dns:
  listen: 127.0.0.1:1053
  upstreams:
    mode: explicit
    addresses: [1.1.1.1:53]
  mark: 4242
policy:
  default: allow
  allow: ["github.com"]
`))
	if err == nil {
		t.Fatal("Load() error = nil, want validation error")
	}
}

func TestLoadConfig_RejectsNestedUnknownYAMLKeys(t *testing.T) {
	_, err := Load([]byte(`
mode: enforce
interface:
  mode: explicit
  name: eth0
dns:
  listen: 127.0.0.1:1053
  upstreams:
    mode: explicit
    addresses: [1.1.1.1:53]
  mark: 4242
  unknownNested: true
policy:
  default: deny
  allow: ["github.com"]
`))
	if err == nil {
		t.Fatal("Load() error = nil, want unknown field error")
	}
}

func TestLoadConfig_RejectsTrailingYAMLDocumentsOrContent(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{
			name: "multi-document",
			raw: `
mode: enforce
interface:
  mode: explicit
  name: eth0
dns:
  listen: 127.0.0.1:1053
  upstreams:
    mode: explicit
    addresses: [1.1.1.1:53]
  mark: 4242
policy:
  default: deny
  allow: ["github.com"]
---
mode: audit
`,
		},
		{
			name: "trailing-content",
			raw: `
mode: enforce
interface:
  mode: explicit
  name: eth0
dns:
  listen: 127.0.0.1:1053
  upstreams:
    mode: explicit
    addresses: [1.1.1.1:53]
  mark: 4242
policy:
  default: deny
  allow: ["github.com"]
true
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load([]byte(tt.raw))
			if err == nil {
				t.Fatal("Load() error = nil, want trailing content error")
			}
		})
	}
}

func TestLoadConfig_TrimsModeAndPolicyDefault(t *testing.T) {
	cfg, err := Load([]byte(`
mode: " enforce "
interface:
  mode: explicit
  name: eth0
dns:
  listen: 127.0.0.1:1053
  upstreams:
    mode: explicit
    addresses: [1.1.1.1:53]
  mark: 4242
policy:
  default: " deny "
  allow: ["github.com"]
https:
  ports: [443]
`))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Mode != ModeEnforce {
		t.Fatalf("Mode = %q, want %q", cfg.Mode, ModeEnforce)
	}
	if cfg.Policy.Default != "deny" {
		t.Fatalf("Policy.Default = %q, want %q", cfg.Policy.Default, "deny")
	}
}

func TestLoadConfig_EmptyInputReturnsDomainError(t *testing.T) {
	_, err := Load(nil)
	if !errors.Is(err, ErrEmptyConfig) {
		t.Fatalf("Load(nil) error = %v, want errors.Is(err, ErrEmptyConfig)", err)
	}
}

func TestLoadConfig_RejectsMissingOrZeroDNSMark(t *testing.T) {
	tests := []struct {
		name   string
		config string
	}{
		{
			name: "missing",
			config: `
mode: enforce
interface:
  mode: explicit
  name: eth0
dns:
  listen: 127.0.0.1:1053
  upstreams:
    mode: explicit
    addresses: [1.1.1.1:53]
policy:
  default: deny
  allow: ["github.com"]
`,
		},
		{
			name: "zero",
			config: `
mode: enforce
interface:
  mode: explicit
  name: eth0
dns:
  listen: 127.0.0.1:1053
  upstreams:
    mode: explicit
    addresses: [1.1.1.1:53]
  mark: 0
policy:
  default: deny
  allow: ["github.com"]
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

func TestLoadConfig_AcceptsPositiveDNSMark(t *testing.T) {
	cfg, err := Load([]byte(`
mode: enforce
interface:
  mode: explicit
  name: eth0
dns:
  listen: 127.0.0.1:1053
  upstreams:
    mode: explicit
    addresses: [1.1.1.1:53]
  mark: 4242
policy:
  default: deny
  allow: ["github.com"]
https:
  ports: [443]
`))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.DNS.Mark != 4242 {
		t.Fatalf("DNS.Mark = %d, want %d", cfg.DNS.Mark, 4242)
	}
}

func TestLoadConfig_RejectsDuplicateTopLevelKeys(t *testing.T) {
	_, err := Load([]byte(`
mode: enforce
mode: audit
interface:
  mode: explicit
  name: eth0
dns:
  listen: 127.0.0.1:1053
  upstreams:
    mode: explicit
    addresses: [1.1.1.1:53]
  mark: 4242
policy:
  default: deny
  allow: ["github.com"]
https:
  ports: [443]
`))
	if err == nil {
		t.Fatal("Load() error = nil, want duplicate key error")
	}
	if !strings.Contains(err.Error(), "mapping key") || !strings.Contains(err.Error(), "already defined") {
		t.Fatalf("Load() error = %v, want duplicate-key reason", err)
	}
}

func TestLoadConfig_RejectsDuplicateNestedKeys(t *testing.T) {
	_, err := Load([]byte(`
mode: enforce
interface:
  mode: explicit
  name: eth0
dns:
  listen: 127.0.0.1:1053
  listen: 0.0.0.0:1053
  upstreams:
    mode: explicit
    addresses: [1.1.1.1:53]
  mark: 4242
policy:
  default: deny
  allow: ["github.com"]
`))
	if err == nil {
		t.Fatal("Load() error = nil, want duplicate key error")
	}
	if !strings.Contains(err.Error(), "mapping key") || !strings.Contains(err.Error(), "already defined") {
		t.Fatalf("Load() error = %v, want duplicate-key reason", err)
	}
}

func TestLoadConfig_RejectsInvalidDNSListenHostPort(t *testing.T) {
	tests := []struct {
		name      string
		listen    string
		wantError string
	}{
		{name: "missing port", listen: "127.0.0.1", wantError: "missing port in address"},
		{name: "non numeric port", listen: "127.0.0.1:http", wantError: "numeric port"},
		{name: "zero port", listen: "127.0.0.1:0", wantError: "1-65535"},
		{name: "out of range port", listen: "127.0.0.1:70000", wantError: "1-65535"},
		{name: "missing host", listen: ":1053", wantError: "must include a host"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := []byte(`
mode: enforce
interface:
  mode: explicit
  name: eth0
dns:
  listen: ` + tt.listen + `
  upstreams:
    mode: explicit
    addresses: [1.1.1.1:53]
  mark: 4242
policy:
  default: deny
  allow: ["github.com"]
`)

			_, err := Load(raw)
			if err == nil {
				t.Fatal("Load() error = nil, want validation error")
			}
			if !strings.Contains(err.Error(), "dns.listen") {
				t.Fatalf("Load() error = %v, want dns.listen field context", err)
			}
			if !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("Load() error = %v, want reason containing %q", err, tt.wantError)
			}
		})
	}
}

func TestLoadConfig_RejectsInvalidDNSUpstreamsHostPort(t *testing.T) {
	tests := []struct {
		name      string
		upstream  string
		wantError string
	}{
		{name: "missing port", upstream: "1.1.1.1", wantError: "missing port in address"},
		{name: "non numeric port", upstream: "1.1.1.1:http", wantError: "numeric port"},
		{name: "zero port", upstream: "1.1.1.1:0", wantError: "1-65535"},
		{name: "out of range port", upstream: "1.1.1.1:70000", wantError: "1-65535"},
		{name: "missing host", upstream: `":53"`, wantError: "must include a host"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := []byte(`
mode: enforce
interface:
  mode: explicit
  name: eth0
dns:
  listen: 127.0.0.1:1053
  upstreams:
    mode: explicit
    addresses: [` + tt.upstream + `]
  mark: 4242
policy:
  default: deny
  allow: ["github.com"]
`)

			_, err := Load(raw)
			if err == nil {
				t.Fatal("Load() error = nil, want validation error")
			}
			if !strings.Contains(err.Error(), "dns.upstreams") {
				t.Fatalf("Load() error = %v, want dns.upstreams field context", err)
			}
			if !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("Load() error = %v, want reason containing %q", err, tt.wantError)
			}
		})
	}
}

func TestLoadConfig_AcceptsValidDNSHostPortValues(t *testing.T) {
	_, err := Load([]byte(`
mode: enforce
interface:
  mode: explicit
  name: eth0
dns:
  listen: dns.local:1053
  upstreams:
    mode: explicit
    addresses: [1.1.1.1:53, dns.google:53]
  mark: 4242
policy:
  default: deny
  allow: ["github.com"]
https:
  ports: [443]
`))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
}

func TestLoadConfig_WhitespaceOnlyInputReturnsDomainError(t *testing.T) {
	_, err := Load([]byte("   \n\t  "))
	if !errors.Is(err, ErrEmptyConfig) {
		t.Fatalf("Load(whitespace) error = %v, want errors.Is(err, ErrEmptyConfig)", err)
	}
}

func TestLoadConfig_PolicyAllowNullOrEmptyYieldsNonNilSlice(t *testing.T) {
	tests := []struct {
		name       string
		allowValue string
	}{
		{name: "null", allowValue: "null"},
		{name: "empty", allowValue: "[]"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := Load([]byte(`
mode: enforce
interface:
  mode: explicit
  name: eth0
dns:
  listen: 127.0.0.1:1053
  upstreams:
    mode: explicit
    addresses: [1.1.1.1:53]
  mark: 4242
policy:
  default: deny
  allow: ` + tt.allowValue + `
https:
  ports: [443]
`))
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if cfg.Policy.Allow == nil {
				t.Fatal("Policy.Allow = nil, want non-nil slice")
			}
			if len(cfg.Policy.Allow) != 0 {
				t.Fatalf("len(Policy.Allow) = %d, want 0", len(cfg.Policy.Allow))
			}
		})
	}
}

func TestLoadConfig_RejectsDNSListenBindAllWithoutExplicitHost(t *testing.T) {
	_, err := Load([]byte(`
mode: enforce
interface:
  mode: explicit
  name: eth0
dns:
  listen: ":1053"
  upstreams:
    mode: explicit
    addresses: [1.1.1.1:53]
  mark: 4242
policy:
  default: deny
  allow: ["github.com"]
`))
	if err == nil {
		t.Fatal("Load() error = nil, want validation error")
	}
	if !strings.Contains(err.Error(), "dns.listen") || !strings.Contains(err.Error(), "must include a host") {
		t.Fatalf("Load() error = %v, want explicit-host requirement", err)
	}
}

func TestLoadConfig_InvalidDNSUpstreamErrorMentionsEntryIndex(t *testing.T) {
	_, err := Load([]byte(`
mode: enforce
interface:
  mode: explicit
  name: eth0
dns:
  listen: 127.0.0.1:1053
  upstreams:
    mode: explicit
    addresses: [1.1.1.1:53, 1.1.1.1]
  mark: 4242
policy:
  default: deny
  allow: ["github.com"]
`))
	if err == nil {
		t.Fatal("Load() error = nil, want validation error")
	}
	if !strings.Contains(err.Error(), "dns.upstreams.addresses[1]") {
		t.Fatalf("Load() error = %v, want failing upstream address index in error", err)
	}
}

func TestLoadConfig_InvalidPolicyAllowErrorMentionsEntryIndex(t *testing.T) {
	_, err := Load([]byte(`
mode: enforce
interface:
  mode: explicit
  name: eth0
dns:
  listen: 127.0.0.1:1053
  upstreams:
    mode: explicit
    addresses: [1.1.1.1:53]
  mark: 4242
policy:
  default: deny
  allow: ["github.com", "   "]
`))
	if err == nil {
		t.Fatal("Load() error = nil, want validation error")
	}
	if !strings.Contains(err.Error(), "policy.allow[1]") {
		t.Fatalf("Load() error = %v, want failing allow index in error", err)
	}
}

func TestLoadConfig_AcceptsTrustDurations(t *testing.T) {
	cfg, err := Load([]byte(`
mode: enforce
interface:
  mode: explicit
  name: eth0
dns:
  listen: 127.0.0.1:1053
  upstreams:
    mode: explicit
    addresses: [1.1.1.1:53]
  mark: 4242
policy:
  default: deny
  allow: ["github.com"]
https:
  ports: [443]
trust:
  max_stale_hold: 2m30s
  sweep_interval: 15s
`))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Trust.MaxStaleHold != 2*time.Minute+30*time.Second {
		t.Fatalf("Trust.MaxStaleHold = %s, want 2m30s", cfg.Trust.MaxStaleHold)
	}
	if cfg.Trust.SweepInterval != 15*time.Second {
		t.Fatalf("Trust.SweepInterval = %s, want 15s", cfg.Trust.SweepInterval)
	}
}

func TestLoadConfig_RejectsNegativeTrustMaxStaleHold(t *testing.T) {
	_, err := Load([]byte(`
mode: enforce
interface:
  mode: explicit
  name: eth0
dns:
  listen: 127.0.0.1:1053
  upstreams:
    mode: explicit
    addresses: [1.1.1.1:53]
  mark: 4242
policy:
  default: deny
  allow: ["github.com"]
https:
  ports: [443]
trust:
  max_stale_hold: -1s
`))
	if err == nil {
		t.Fatal("Load() error = nil, want validation error")
	}
	if !strings.Contains(err.Error(), "trust.max_stale_hold") {
		t.Fatalf("Load() error = %v, want trust.max_stale_hold context", err)
	}
}

func TestLoadConfig_RejectsNegativeTrustSweepInterval(t *testing.T) {
	_, err := Load([]byte(`
mode: enforce
interface:
  mode: explicit
  name: eth0
dns:
  listen: 127.0.0.1:1053
  upstreams:
    mode: explicit
    addresses: [1.1.1.1:53]
  mark: 4242
policy:
  default: deny
  allow: ["github.com"]
https:
  ports: [443]
trust:
  sweep_interval: -1s
`))
	if err == nil {
		t.Fatal("Load() error = nil, want validation error")
	}
	if !strings.Contains(err.Error(), "trust.sweep_interval") {
		t.Fatalf("Load() error = %v, want trust.sweep_interval context", err)
	}
}

func TestLoadConfig_RejectsMalformedTrustMaxStaleHold(t *testing.T) {
	_, err := Load([]byte(`
mode: enforce
interface:
  mode: explicit
  name: eth0
dns:
  listen: 127.0.0.1:1053
  upstreams:
    mode: explicit
    addresses: [1.1.1.1:53]
  mark: 4242
policy:
  default: deny
  allow: ["github.com"]
https:
  ports: [443]
trust:
  max_stale_hold: nope
`))
	if err == nil {
		t.Fatal("Load() error = nil, want validation error")
	}
	if !strings.Contains(err.Error(), "trust.max_stale_hold") {
		t.Fatalf("Load() error = %v, want trust.max_stale_hold context", err)
	}
}

func TestLoadConfig_RejectsMalformedTrustSweepInterval(t *testing.T) {
	_, err := Load([]byte(`
mode: enforce
interface:
  mode: explicit
  name: eth0
dns:
  listen: 127.0.0.1:1053
  upstreams:
    mode: explicit
    addresses: [1.1.1.1:53]
  mark: 4242
policy:
  default: deny
  allow: ["github.com"]
https:
  ports: [443]
trust:
  sweep_interval: nope
`))
	if err == nil {
		t.Fatal("Load() error = nil, want validation error")
	}
	if !strings.Contains(err.Error(), "trust.sweep_interval") {
		t.Fatalf("Load() error = %v, want trust.sweep_interval context", err)
	}
}
