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

func TestEngineSingleLabelWildcardDoesNotMatchMultiLevelSubdomain(t *testing.T) {
	engine, err := New([]string{"*.github.com"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if engine.Allows("a.b.github.com") {
		t.Fatal("Allows(a.b.github.com) = true, want false")
	}
}

func TestEngineMultiLabelWildcardMatchesOneOrMoreSubdomainLabels(t *testing.T) {
	engine, err := New([]string{"**.github.com"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if !engine.Allows("a.github.com") {
		t.Fatal("Allows(a.github.com) = false, want true")
	}
	if !engine.Allows("a.b.github.com") {
		t.Fatal("Allows(a.b.github.com) = false, want true")
	}
	if engine.Allows("github.com") {
		t.Fatal("Allows(github.com) = true, want false")
	}
}

func TestEngineBareWildcardMatchesAnyNonEmptyHostname(t *testing.T) {
	engine, err := New([]string{"*"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if !engine.Allows("api.github.com") {
		t.Fatal("Allows(api.github.com) = false, want true")
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
	tests := []string{
		"api.*.github.com",
		"***.github.com",
		"foo*bar.github.com",
		"*github.com",
		"**github.com",
		"github.*.com",
	}
	for _, pattern := range tests {
		_, err := New([]string{pattern})
		if err == nil {
			t.Fatalf("New(%q) error = nil, want non-nil", pattern)
		}
		if !strings.Contains(err.Error(), NormalizeHostname(pattern)) {
			t.Fatalf("New(%q) error = %q, want message containing normalized pattern", pattern, err)
		}
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
