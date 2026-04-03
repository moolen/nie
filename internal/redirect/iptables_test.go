package redirect

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestRenderRulesExactOutput(t *testing.T) {
	const listenPort = 1053

	got := RenderRules(Config{
		ListenPort: listenPort,
		Mark:       4242,
	})

	want := fmt.Sprintf(
		"\n*nat\n-A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports %d\n-A OUTPUT -p tcp --dport 53 -j REDIRECT --to-ports %d\nCOMMIT\n",
		listenPort,
		listenPort,
	)

	if got != want {
		t.Fatalf("unexpected rendered rules\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}

	// Keep the original contract checks to make intent obvious.
	if !strings.Contains(got, "-p udp --dport 53") {
		t.Fatal("missing UDP redirect rule")
	}
	if !strings.Contains(got, "-p tcp --dport 53") {
		t.Fatal("missing TCP redirect rule")
	}
	if !strings.Contains(got, fmt.Sprintf("--to-ports %d", listenPort)) {
		t.Fatal("missing redirect to listen port")
	}
}

func TestRenderRulesParseableByIptablesRestore(t *testing.T) {
	iptablesRestorePath, err := exec.LookPath("iptables-restore")
	if err != nil {
		t.Skip("iptables-restore not found in PATH")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)

	rules := RenderRules(Config{
		ListenPort: 1053,
		Mark:       4242,
	})

	cmd := exec.CommandContext(ctx, iptablesRestorePath, "--test")
	cmd.Stdin = strings.NewReader(rules)

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	if err := cmd.Run(); err != nil {
		t.Fatalf("iptables-restore --test failed: %v\noutput:\n%s", err, out.String())
	}
}
