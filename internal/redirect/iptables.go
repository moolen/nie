package redirect

import (
	"context"
	"fmt"
)

type Config struct {
	ListenPort int
	Mark       uint32
}

func RenderRules(cfg Config) string {
	return fmt.Sprintf(`
*nat
-A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports %d
-A OUTPUT -p tcp --dport 53 -j REDIRECT --to-ports %d
COMMIT
`, cfg.ListenPort, cfg.ListenPort)
}

type Runner interface {
	Run(ctx context.Context, name string, args ...string) error
}
