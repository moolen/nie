package policy

import (
	"strings"
	"testing"
)

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
	engine, err := New([]string{"*.github.com"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if engine.Allows("example.com") {
		t.Fatal("Allows(example.com) = true, want false")
	}
}

func TestEngineWildcardDoesNotMatchApex(t *testing.T) {
	engine, err := New([]string{"*.github.com"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if engine.Allows("github.com") {
		t.Fatal("Allows(github.com) = true, want false")
	}
}

func TestEngineRejectsEmptyNormalizedPattern(t *testing.T) {
	tests := []string{"", "   ", ".", "..."}
	for _, pattern := range tests {
		_, err := New([]string{pattern})
		if err == nil {
			t.Fatalf("New(%q) error = nil, want non-nil", pattern)
		}
		if !strings.Contains(err.Error(), "empty") {
			t.Fatalf("New(%q) error = %q, want message containing %q", pattern, err, "empty")
		}
	}
}

func TestEngineRejectsInvalidPatternWithContext(t *testing.T) {
	_, err := New([]string{" [abc "})
	if err == nil {
		t.Fatal("New() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "[abc") {
		t.Fatalf("New() error = %q, want message containing %q", err, "[abc")
	}
}

func TestEngineDeniesEmptyNormalizedHost(t *testing.T) {
	engine, err := New([]string{"*"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if engine.Allows(" . ") {
		t.Fatal("Allows(\" . \") = true, want false")
	}
}
