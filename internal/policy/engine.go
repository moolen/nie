package policy

import "path"

type Engine struct {
	patterns []string
}

func New(patterns []string) (*Engine, error) {
	normalized := make([]string, 0, len(patterns))
	for _, pattern := range patterns {
		pattern = NormalizeHostname(pattern)
		if _, err := path.Match(pattern, ""); err != nil {
			return nil, err
		}
		normalized = append(normalized, pattern)
	}

	return &Engine{patterns: normalized}, nil
}

func (e *Engine) Allows(host string) bool {
	host = NormalizeHostname(host)
	for _, pattern := range e.patterns {
		if ok, _ := path.Match(pattern, host); ok {
			return true
		}
	}
	return false
}
