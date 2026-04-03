package policy

import "testing"

func TestNormalizeHostname(t *testing.T) {
	got := NormalizeHostname("API.GitHub.Com.")
	if got != "api.github.com" {
		t.Fatalf("NormalizeHostname() = %q", got)
	}
}

func TestEngineAllowsGlobAndExactMatch(t *testing.T) {
	engine, err := New([]string{"*.github.com", "github.com"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if !engine.Allows("api.github.com") {
		t.Fatal("Allows(api.github.com) = false, want true")
	}
	if !engine.Allows("github.com") {
		t.Fatal("Allows(github.com) = false, want true")
	}
}

func TestEngineDeniesUnknownHost(t *testing.T) {
	engine, _ := New([]string{"*.github.com"})
	if engine.Allows("example.com") {
		t.Fatal("Allows(example.com) = true, want false")
	}
}
