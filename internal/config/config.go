package config

import (
	"errors"
	"fmt"

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

func Load(raw []byte) (Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c *Config) Validate() error {
	if c.Policy.Allow == nil {
		c.Policy.Allow = []string{}
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
	if len(c.DNS.Upstreams) == 0 {
		return errors.New("dns.upstreams must contain at least one upstream")
	}
	if c.Policy.Default != "deny" {
		return fmt.Errorf("invalid policy.default %q", c.Policy.Default)
	}
	return nil
}
