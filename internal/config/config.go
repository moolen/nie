package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type Mode string

const (
	ModeEnforce Mode = "enforce"
	ModeAudit   Mode = "audit"
)

type Config struct {
	Mode      Mode   `yaml:"mode"`
	Interface string `yaml:"interface"`
	DNS       DNS    `yaml:"dns"`
	Policy    Policy `yaml:"policy"`
	HTTPS     HTTPS  `yaml:"https"`
}

type DNS struct {
	Listen    string   `yaml:"listen"`
	Upstreams []string `yaml:"upstreams"`
	Mark      int      `yaml:"mark"`
}

type Policy struct {
	Default string   `yaml:"default"`
	Allow   []string `yaml:"allow"`
}

type HTTPS struct {
	Listen string    `yaml:"listen"`
	Ports  []int     `yaml:"ports"`
	SNI    HTTPSSNI  `yaml:"sni"`
	CA     HTTPSCA   `yaml:"ca"`
	MITM   HTTPSMITM `yaml:"mitm"`
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
	httpsProvided := c.httpsConfigured()

	c.Mode = Mode(strings.TrimSpace(string(c.Mode)))
	c.Interface = strings.TrimSpace(c.Interface)
	c.DNS.Listen = strings.TrimSpace(c.DNS.Listen)
	c.Policy.Default = strings.TrimSpace(c.Policy.Default)
	c.HTTPS.Listen = strings.TrimSpace(c.HTTPS.Listen)
	c.HTTPS.SNI.Missing = strings.TrimSpace(c.HTTPS.SNI.Missing)
	c.HTTPS.CA.CertFile = strings.TrimSpace(c.HTTPS.CA.CertFile)
	c.HTTPS.CA.KeyFile = strings.TrimSpace(c.HTTPS.CA.KeyFile)
	c.HTTPS.MITM.Default = strings.TrimSpace(c.HTTPS.MITM.Default)

	if c.HTTPS.Listen == "" {
		c.HTTPS.Listen = "127.0.0.1:9443"
	}
	if c.HTTPS.SNI.Missing == "" {
		c.HTTPS.SNI.Missing = "deny"
	}
	if c.HTTPS.CA.CertFile == "" {
		c.HTTPS.CA.CertFile = "/var/lib/nie/ca/root.crt"
	}
	if c.HTTPS.CA.KeyFile == "" {
		c.HTTPS.CA.KeyFile = "/var/lib/nie/ca/root.key"
	}
	if c.HTTPS.MITM.Default == "" {
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

	for i, upstream := range c.DNS.Upstreams {
		c.DNS.Upstreams[i] = strings.TrimSpace(upstream)
	}

	switch c.Mode {
	case ModeEnforce, ModeAudit:
	default:
		return fmt.Errorf("invalid mode %q", c.Mode)
	}
	if c.Interface == "" {
		return errors.New("interface must be set")
	}
	if c.DNS.Listen == "" {
		return errors.New("dns.listen must be set")
	}
	if err := validateHostPort("dns.listen", c.DNS.Listen); err != nil {
		return err
	}
	if len(c.DNS.Upstreams) == 0 {
		return errors.New("dns.upstreams must contain at least one upstream")
	}
	for i, upstream := range c.DNS.Upstreams {
		if upstream == "" {
			return fmt.Errorf("dns.upstreams[%d] must not be empty", i)
		}
		if err := validateHostPort(fmt.Sprintf("dns.upstreams[%d]", i), upstream); err != nil {
			return err
		}
	}
	if c.DNS.Mark <= 0 {
		return errors.New("dns.mark must be a positive non-zero value")
	}
	if c.Policy.Default != "deny" {
		return fmt.Errorf("invalid policy.default %q", c.Policy.Default)
	}

	if !httpsProvided {
		return nil
	}
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
	return nil
}

func (c Config) httpsConfigured() bool {
	if c.HTTPS.Listen != "" || len(c.HTTPS.Ports) > 0 || c.HTTPS.SNI.Missing != "" {
		return true
	}
	if c.HTTPS.CA.CertFile != "" || c.HTTPS.CA.KeyFile != "" {
		return true
	}
	if c.HTTPS.MITM.Default != "" || len(c.HTTPS.MITM.Rules) > 0 {
		return true
	}
	return false
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
