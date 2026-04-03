package policy

import (
	"fmt"
	"path"
)

type Engine struct {
	patterns []string
}

func New(patterns []string) (*Engine, error) {
	normalized := make([]string, 0, len(patterns))
	for _, rawPattern := range patterns {
		pattern := NormalizeHostname(rawPattern)
		if pattern == "" {
			return nil, fmt.Errorf("empty hostname pattern after normalization: %q", rawPattern)
		}
		if _, err := path.Match(pattern, ""); err != nil {
			return nil, fmt.Errorf("invalid hostname pattern %q: %w", pattern, err)
		}
		normalized = append(normalized, pattern)
	}

	return &Engine{patterns: normalized}, nil
}

func (e *Engine) Allows(host string) bool {
	host = NormalizeHostname(host)
	if host == "" {
		return false
	}
	for _, pattern := range e.patterns {
		if ok, _ := path.Match(pattern, host); ok {
			return true
		}
	}
	return false
}
