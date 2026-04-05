package redirect

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestRenderRulesExactOutput(t *testing.T) {
	const (
		dnsListenPort   = 1053
		httpsListenPort = 9443
	)

	got := RenderRules(Config{
		DNSListenPort:   dnsListenPort,
		HTTPSListenPort: httpsListenPort,
		HTTPSPorts:      []int{443, 8443},
		Mark:            4242,
	})

	want := fmt.Sprintf(
		"\n*nat\n-A OUTPUT -m mark ! --mark 4242 -p udp --dport 53 -j REDIRECT --to-ports %d\n-A OUTPUT -m mark ! --mark 4242 -p tcp --dport 53 -j REDIRECT --to-ports %d\n-A OUTPUT -m mark ! --mark 4242 -p tcp --dport 443 -j REDIRECT --to-ports %d\n-A OUTPUT -m mark ! --mark 4242 -p tcp --dport 8443 -j REDIRECT --to-ports %d\nCOMMIT\n",
		dnsListenPort,
		dnsListenPort,
		httpsListenPort,
		httpsListenPort,
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
	if !strings.Contains(got, fmt.Sprintf("--to-ports %d", dnsListenPort)) {
		t.Fatal("missing redirect to DNS listen port")
	}
	if !strings.Contains(got, fmt.Sprintf("--dport 443 -j REDIRECT --to-ports %d", httpsListenPort)) {
		t.Fatal("missing redirect for HTTPS port 443")
	}
	if !strings.Contains(got, "-m mark ! --mark 4242") {
		t.Fatal("missing bypass mark exclusion")
	}
}

func TestRenderRulesParseableByIptablesRestore(t *testing.T) {
	iptablesRestorePath, err := exec.LookPath("iptables-restore")
	if err != nil {
		t.Skip("iptables-restore not found in PATH")
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root to run iptables-restore --test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)

	rules := RenderRules(Config{
		DNSListenPort:   1053,
		HTTPSListenPort: 9443,
		HTTPSPorts:      []int{443},
		Mark:            4242,
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
