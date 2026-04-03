package policy

import (
	"fmt"
	"strings"
)

type Engine struct {
	patterns []compiledPattern
}

type patternKind int

const (
	patternExact patternKind = iota
	patternAny
	patternSingleLabelSubdomain
	patternAnyDepthSubdomain
)

type compiledPattern struct {
	kind  patternKind
	value string
}

// New builds a hostname policy engine that accepts:
// - exact hostnames (for example: "github.com")
// - "*" (any non-empty hostname)
// - "*.example.com" (exactly one label under example.com)
// - "**.example.com" (one or more labels under example.com)
func New(patterns []string) (*Engine, error) {
	compiled := make([]compiledPattern, 0, len(patterns))
	for _, rawPattern := range patterns {
		pattern := NormalizeHostname(rawPattern)
		if pattern == "" {
			return nil, fmt.Errorf("empty hostname pattern after normalization: %q", rawPattern)
		}

		parsed, err := parsePattern(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid hostname pattern %q: %w", pattern, err)
		}
		compiled = append(compiled, parsed)
	}

	return &Engine{patterns: compiled}, nil
}

func (e *Engine) Allows(host string) bool {
	host = NormalizeHostname(host)
	if host == "" {
		return false
	}
	if !isValidHostname(host) {
		return false
	}

	for _, pattern := range e.patterns {
		if matchesPattern(pattern, host) {
			return true
		}
	}
	return false
}

func parsePattern(pattern string) (compiledPattern, error) {
	switch {
	case pattern == "*":
		return compiledPattern{kind: patternAny}, nil
	case strings.HasPrefix(pattern, "**."):
		if strings.Count(pattern, "*") != 2 {
			return compiledPattern{}, fmt.Errorf("unsupported wildcard form")
		}
		base := strings.TrimPrefix(pattern, "**.")
		if !isValidHostname(base) {
			return compiledPattern{}, fmt.Errorf("invalid base hostname")
		}
		return compiledPattern{kind: patternAnyDepthSubdomain, value: base}, nil
	case strings.HasPrefix(pattern, "*."):
		if strings.Count(pattern, "*") != 1 {
			return compiledPattern{}, fmt.Errorf("unsupported wildcard form")
		}
		base := strings.TrimPrefix(pattern, "*.")
		if !isValidHostname(base) {
			return compiledPattern{}, fmt.Errorf("invalid base hostname")
		}
		return compiledPattern{kind: patternSingleLabelSubdomain, value: base}, nil
	case strings.Contains(pattern, "*"):
		return compiledPattern{}, fmt.Errorf("unsupported wildcard form")
	default:
		if !isValidHostname(pattern) {
			return compiledPattern{}, fmt.Errorf("invalid hostname syntax")
		}
		return compiledPattern{kind: patternExact, value: pattern}, nil
	}
}

func matchesPattern(pattern compiledPattern, host string) bool {
	switch pattern.kind {
	case patternAny:
		return host != ""
	case patternExact:
		return host == pattern.value
	case patternSingleLabelSubdomain:
		prefix, ok := trimSubdomainPrefix(host, pattern.value)
		return ok && !strings.Contains(prefix, ".")
	case patternAnyDepthSubdomain:
		_, ok := trimSubdomainPrefix(host, pattern.value)
		return ok
	default:
		return false
	}
}

func trimSubdomainPrefix(host, base string) (string, bool) {
	suffix := "." + base
	if !strings.HasSuffix(host, suffix) {
		return "", false
	}
	prefix := strings.TrimSuffix(host, suffix)
	if prefix == "" {
		return "", false
	}
	return prefix, true
}

func isValidHostname(host string) bool {
	labels := strings.Split(host, ".")
	if len(labels) == 0 {
		return false
	}
	for _, label := range labels {
		if !isValidLabel(label) {
			return false
		}
	}
	return true
}

func isValidLabel(label string) bool {
	if label == "" {
		return false
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, ch := range label {
		if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' {
			continue
		}
		return false
	}
	return true
}
