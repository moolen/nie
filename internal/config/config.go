package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Mode string

const (
	ModeEnforce Mode = "enforce"
	ModeAudit   Mode = "audit"
)

type Config struct {
	Mode      Mode              `yaml:"mode"`
	Interface InterfaceSelector `yaml:"interface"`
	DNS       DNS               `yaml:"dns"`
	Policy    Policy            `yaml:"policy"`
	HTTPS     HTTPS             `yaml:"https"`
	Trust     Trust             `yaml:"trust"`
}

type InterfaceSelector struct {
	Mode string `yaml:"mode"`
	Name string `yaml:"name"`
}

type DNS struct {
	Listen    string           `yaml:"listen"`
	Upstreams UpstreamSelector `yaml:"upstreams"`
	Mark      int              `yaml:"mark"`
}

type UpstreamSelector struct {
	Mode      string   `yaml:"mode"`
	Addresses []string `yaml:"addresses"`
}

type Policy struct {
	Default string   `yaml:"default"`
	Allow   []string `yaml:"allow"`
}

type HTTPS struct {
	configured bool      `yaml:"-"`
	Listen     string    `yaml:"listen"`
	Ports      []int     `yaml:"ports"`
	SNI        HTTPSSNI  `yaml:"sni"`
	CA         HTTPSCA   `yaml:"ca"`
	MITM       HTTPSMITM `yaml:"mitm"`
}

type HTTPSSNI struct {
	Missing string `yaml:"missing"`
}

type HTTPSCA struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

type HTTPSMITM struct {
	Default string          `yaml:"default"`
	Rules   []HTTPSMITMRule `yaml:"rules"`
}

type HTTPSMITMRule struct {
	Host    string   `yaml:"host"`
	Port    int      `yaml:"port"`
	Methods []string `yaml:"methods"`
	Paths   []string `yaml:"paths"`
	Action  string   `yaml:"action"`
}

func (h *HTTPS) UnmarshalYAML(value *yaml.Node) error {
	type rawHTTPS HTTPS
	if value.Tag == "!!null" {
		*h = HTTPS{}
		return nil
	}

	var raw rawHTTPS
	if err := value.Decode(&raw); err != nil {
		return err
	}

	*h = HTTPS(raw)
	h.configured = true
	return nil
}

func (h HTTPS) Configured() bool {
	if h.configured {
		return true
	}
	return h.Listen != "" ||
		len(h.Ports) != 0 ||
		h.SNI.Missing != "" ||
		h.CA.CertFile != "" ||
		h.CA.KeyFile != "" ||
		h.MITM.Default != "" ||
		len(h.MITM.Rules) != 0
}

type Trust struct {
	MaxStaleHold  time.Duration `yaml:"max_stale_hold"`
	SweepInterval time.Duration `yaml:"sweep_interval"`
}

func (t *Trust) UnmarshalYAML(value *yaml.Node) error {
	*t = Trust{}
	if value.Tag == "!!null" {
		return nil
	}
	if value.Kind != yaml.MappingNode {
		return errors.New("trust must be a mapping")
	}
	for i := 0; i < len(value.Content); i += 2 {
		keyNode := value.Content[i]
		valueNode := value.Content[i+1]

		switch keyNode.Value {
		case "max_stale_hold":
			duration, err := parseDurationNode(valueNode, "trust.max_stale_hold")
			if err != nil {
				return err
			}
			t.MaxStaleHold = duration
		case "sweep_interval":
			duration, err := parseDurationNode(valueNode, "trust.sweep_interval")
			if err != nil {
				return err
			}
			t.SweepInterval = duration
		default:
			return fmt.Errorf("field %s not found in type config.Trust", keyNode.Value)
		}
	}
	return nil
}

var ErrEmptyConfig = errors.New("config is empty")

func Load(raw []byte) (Config, error) {
	var cfg Config
	if len(bytes.TrimSpace(raw)) == 0 {
		return Config{}, ErrEmptyConfig
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		if err == io.EOF {
			return Config{}, ErrEmptyConfig
		}
		return Config{}, err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err != nil {
			return Config{}, err
		}
		return Config{}, errors.New("config must contain exactly one YAML document")
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c *Config) Validate() error {
	c.Mode = Mode(strings.TrimSpace(string(c.Mode)))
	c.Interface.Mode = strings.TrimSpace(c.Interface.Mode)
	c.Interface.Name = strings.TrimSpace(c.Interface.Name)
	c.DNS.Listen = strings.TrimSpace(c.DNS.Listen)
	c.Policy.Default = strings.TrimSpace(c.Policy.Default)
	c.HTTPS.Listen = strings.TrimSpace(c.HTTPS.Listen)
	c.HTTPS.SNI.Missing = strings.TrimSpace(c.HTTPS.SNI.Missing)
	c.HTTPS.CA.CertFile = strings.TrimSpace(c.HTTPS.CA.CertFile)
	c.HTTPS.CA.KeyFile = strings.TrimSpace(c.HTTPS.CA.KeyFile)
	c.HTTPS.MITM.Default = strings.TrimSpace(c.HTTPS.MITM.Default)
	c.DNS.Upstreams.Mode = strings.TrimSpace(c.DNS.Upstreams.Mode)
	httpsConfigured := c.HTTPS.Configured()

	if httpsConfigured && c.HTTPS.Listen == "" {
		c.HTTPS.Listen = "127.0.0.1:9443"
	}
	if httpsConfigured && c.HTTPS.SNI.Missing == "" {
		c.HTTPS.SNI.Missing = "deny"
	}
	if httpsConfigured && c.HTTPS.CA.CertFile == "" {
		c.HTTPS.CA.CertFile = "/var/lib/nie/ca/root.crt"
	}
	if httpsConfigured && c.HTTPS.CA.KeyFile == "" {
		c.HTTPS.CA.KeyFile = "/var/lib/nie/ca/root.key"
	}
	if httpsConfigured && c.HTTPS.MITM.Default == "" {
		c.HTTPS.MITM.Default = "deny"
	}

	if c.Policy.Allow == nil {
		c.Policy.Allow = []string{}
	} else {
		for i, allow := range c.Policy.Allow {
			trimmed := strings.TrimSpace(allow)
			if trimmed == "" {
				return fmt.Errorf("policy.allow[%d] must not be empty", i)
			}
			c.Policy.Allow[i] = trimmed
		}
	}

	for i, upstream := range c.DNS.Upstreams.Addresses {
		c.DNS.Upstreams.Addresses[i] = strings.TrimSpace(upstream)
	}

	switch c.Mode {
	case ModeEnforce, ModeAudit:
	default:
		return fmt.Errorf("invalid mode %q", c.Mode)
	}
	switch c.Interface.Mode {
	case "explicit":
		if c.Interface.Name == "" {
			return errors.New("interface.name must be set when interface.mode=explicit")
		}
	case "auto":
		if c.Interface.Name != "" {
			return errors.New("interface.name must be empty when interface.mode=auto")
		}
	default:
		return errors.New("interface.mode must be one of explicit or auto")
	}
	if c.DNS.Listen == "" {
		return errors.New("dns.listen must be set")
	}
	if err := validateHostPort("dns.listen", c.DNS.Listen); err != nil {
		return err
	}
	switch c.DNS.Upstreams.Mode {
	case "explicit":
		if len(c.DNS.Upstreams.Addresses) == 0 {
			return errors.New("dns.upstreams.addresses must contain at least one upstream when dns.upstreams.mode=explicit")
		}
		for i, upstream := range c.DNS.Upstreams.Addresses {
			if upstream == "" {
				return fmt.Errorf("dns.upstreams.addresses[%d] must not be empty", i)
			}
			if err := validateHostPort(fmt.Sprintf("dns.upstreams.addresses[%d]", i), upstream); err != nil {
				return err
			}
		}
	case "auto":
		if len(c.DNS.Upstreams.Addresses) != 0 {
			return errors.New("dns.upstreams.addresses must be empty when dns.upstreams.mode=auto")
		}
	default:
		return errors.New("dns.upstreams.mode must be one of explicit or auto")
	}
	if c.DNS.Mark <= 0 {
		return errors.New("dns.mark must be a positive non-zero value")
	}
	if c.Policy.Default != "deny" {
		return fmt.Errorf("invalid policy.default %q", c.Policy.Default)
	}

	if httpsConfigured {
		if err := validateHostPort("https.listen", c.HTTPS.Listen); err != nil {
			return err
		}
		if len(c.HTTPS.Ports) == 0 {
			return errors.New("https.ports must contain at least one port")
		}
		seenHTTPSPorts := make(map[int]struct{}, len(c.HTTPS.Ports))
		for i, port := range c.HTTPS.Ports {
			if port < 1 || port > 65535 {
				return fmt.Errorf("https.ports[%d] has out-of-range port %d (must be 1-65535)", i, port)
			}
			if _, exists := seenHTTPSPorts[port]; exists {
				return fmt.Errorf("https.ports[%d] duplicates port %d", i, port)
			}
			seenHTTPSPorts[port] = struct{}{}
		}
		switch c.HTTPS.SNI.Missing {
		case "deny", "audit":
		default:
			return fmt.Errorf("invalid https.sni.missing %q", c.HTTPS.SNI.Missing)
		}
		switch c.HTTPS.MITM.Default {
		case "deny", "audit":
		default:
			return fmt.Errorf("invalid https.mitm.default %q", c.HTTPS.MITM.Default)
		}
		for i := range c.HTTPS.MITM.Rules {
			rule := &c.HTTPS.MITM.Rules[i]
			rule.Host = strings.TrimSpace(rule.Host)
			rule.Action = strings.TrimSpace(rule.Action)
			if rule.Host == "" {
				return fmt.Errorf("https.mitm.rules[%d].host must not be empty", i)
			}
			if rule.Port < 1 {
				return fmt.Errorf("https.mitm.rules[%d].port must be a positive non-zero value", i)
			}
			if rule.Port > 65535 {
				return fmt.Errorf("https.mitm.rules[%d].port has out-of-range port %d (must be 1-65535)", i, rule.Port)
			}
			if len(rule.Methods) == 0 {
				return fmt.Errorf("https.mitm.rules[%d].methods must contain at least one method", i)
			}
			for j, method := range rule.Methods {
				method = strings.TrimSpace(method)
				if method == "" {
					return fmt.Errorf("https.mitm.rules[%d].methods[%d] must not be empty", i, j)
				}
				rule.Methods[j] = method
			}
			if len(rule.Paths) == 0 {
				return fmt.Errorf("https.mitm.rules[%d].paths must contain at least one path", i)
			}
			for j, path := range rule.Paths {
				path = strings.TrimSpace(path)
				if path == "" {
					return fmt.Errorf("https.mitm.rules[%d].paths[%d] must not be empty", i, j)
				}
				rule.Paths[j] = path
			}
			switch rule.Action {
			case "allow", "deny", "audit":
			default:
				return fmt.Errorf("invalid https.mitm.rules[%d].action %q", i, rule.Action)
			}
		}
	}
	if c.Trust.MaxStaleHold < 0 {
		return errors.New("trust.max_stale_hold must be greater than or equal to 0")
	}
	if c.Trust.SweepInterval < 0 {
		return errors.New("trust.sweep_interval must be greater than or equal to 0")
	}
	return nil
}

func validateHostPort(field, value string) error {
	host, portStr, err := net.SplitHostPort(value)
	if err != nil {
		return fmt.Errorf("%s value %q must be a valid host:port value: %w", field, value, err)
	}
	if host == "" {
		return fmt.Errorf("%s value %q must include a host", field, value)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("%s value %q must include a numeric port: %w", field, value, err)
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("%s value %q has out-of-range port %d (must be 1-65535)", field, value, port)
	}
	return nil
}

func parseDurationNode(node *yaml.Node, field string) (time.Duration, error) {
	if node.Tag == "!!null" {
		return 0, nil
	}

	var raw string
	if err := node.Decode(&raw); err != nil {
		return 0, fmt.Errorf("%s must be a valid duration: %w", field, err)
	}

	duration, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s must be a valid duration: %w", field, err)
	}

	return duration, nil
}
