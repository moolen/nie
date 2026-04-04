package redirect

import (
	"context"
	"fmt"
	"strings"
)

type Config struct {
	DNSListenPort   int
	HTTPSListenPort int
	HTTPSPorts      []int
	Mark            uint32
}

func RenderRules(cfg Config) string {
	var b strings.Builder
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "*nat")
	fmt.Fprintf(&b, "-A OUTPUT -m mark ! --mark %d -p udp --dport 53 -j REDIRECT --to-ports %d\n", cfg.Mark, cfg.DNSListenPort)
	fmt.Fprintf(&b, "-A OUTPUT -m mark ! --mark %d -p tcp --dport 53 -j REDIRECT --to-ports %d\n", cfg.Mark, cfg.DNSListenPort)
	for _, port := range cfg.HTTPSPorts {
		fmt.Fprintf(&b, "-A OUTPUT -m mark ! --mark %d -p tcp --dport %d -j REDIRECT --to-ports %d\n", cfg.Mark, port, cfg.HTTPSListenPort)
	}
	fmt.Fprintln(&b, "COMMIT")
	return b.String()
}

type Runner interface {
	Run(ctx context.Context, name string, args ...string) error
}
