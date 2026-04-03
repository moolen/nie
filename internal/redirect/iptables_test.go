package redirect

import (
	"strings"
	"testing"
)

func TestRenderRulesIncludesUDPAndTCPRedirect(t *testing.T) {
	rules := RenderRules(Config{
		ListenPort: 1053,
		Mark:       4242,
	})

	if !strings.Contains(rules, "-p udp --dport 53") {
		t.Fatal("missing UDP redirect rule")
	}
	if !strings.Contains(rules, "-p tcp --dport 53") {
		t.Fatal("missing TCP redirect rule")
	}
}
