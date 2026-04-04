package httppolicy

import (
	"fmt"
	"strings"

	"github.com/moolen/nie/internal/policy"
)

type Action string

const (
	ActionAllow Action = "allow"
	ActionDeny  Action = "deny"
	ActionAudit Action = "audit"
)

type Rule struct {
	Host    string
	Port    uint16
	Methods []string
	Paths   []string
	Action  Action
}

type Request struct {
	Host   string
	Port   uint16
	Method string
	Path   string
}

type Decision struct {
	Action Action
}

type Engine struct {
	rules []compiledRule
}

type compiledRule struct {
	host    *policy.Engine
	port    uint16
	methods map[string]struct{}
	paths   []pathPattern
	action  Action
}

type pathPattern struct {
	segments []string
}

func New(rules []Rule) (*Engine, error) {
	compiled := make([]compiledRule, 0, len(rules))
	for i, rule := range rules {
		if !isValidAction(rule.Action) {
			return nil, fmt.Errorf("rule %d: invalid action %q", i, rule.Action)
		}
		if rule.Port == 0 {
			return nil, fmt.Errorf("rule %d: port must be greater than zero", i)
		}
		if len(rule.Methods) == 0 {
			return nil, fmt.Errorf("rule %d: methods must not be empty", i)
		}
		if len(rule.Paths) == 0 {
			return nil, fmt.Errorf("rule %d: paths must not be empty", i)
		}

		host, err := policy.New([]string{rule.Host})
		if err != nil {
			return nil, fmt.Errorf("rule %d: invalid host pattern %q: %w", i, rule.Host, err)
		}

		methods := make(map[string]struct{}, len(rule.Methods))
		for _, method := range rule.Methods {
			method = strings.ToUpper(strings.TrimSpace(method))
			if method == "" {
				return nil, fmt.Errorf("rule %d: empty method pattern", i)
			}
			methods[method] = struct{}{}
		}

		paths := make([]pathPattern, 0, len(rule.Paths))
		for _, rawPath := range rule.Paths {
			path, err := compilePathPattern(rawPath)
			if err != nil {
				return nil, fmt.Errorf("rule %d: invalid path pattern %q: %w", i, rawPath, err)
			}
			paths = append(paths, path)
		}

		compiled = append(compiled, compiledRule{
			host:    host,
			port:    rule.Port,
			methods: methods,
			paths:   paths,
			action:  rule.Action,
		})
	}

	return &Engine{rules: compiled}, nil
}

func (e *Engine) Evaluate(req Request) (Decision, bool) {
	normalizedMethod := strings.ToUpper(strings.TrimSpace(req.Method))
	normalizedPath := normalizePath(req.Path)

	for _, rule := range e.rules {
		if !rule.host.Allows(req.Host) {
			continue
		}
		if req.Port != rule.port {
			continue
		}
		if len(rule.methods) > 0 {
			if _, ok := rule.methods[normalizedMethod]; !ok {
				continue
			}
		}
		if len(rule.paths) > 0 {
			matched := false
			for _, path := range rule.paths {
				if path.matches(normalizedPath) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		return Decision{Action: rule.action}, true
	}

	return Decision{}, false
}

func isValidAction(action Action) bool {
	switch action {
	case ActionAllow, ActionDeny, ActionAudit:
		return true
	default:
		return false
	}
}

func compilePathPattern(pattern string) (pathPattern, error) {
	pattern = normalizePath(pattern)
	if pattern == "" {
		return pathPattern{}, fmt.Errorf("empty path pattern")
	}
	return pathPattern{segments: splitPath(pattern)}, nil
}

func normalizePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return path
}

func splitPath(path string) []string {
	return strings.Split(path, "/")
}

func (p pathPattern) matches(path string) bool {
	segments := splitPath(path)
	return matchPathSegments(p.segments, segments)
}

func matchPathSegments(pattern, path []string) bool {
	return matchPathSegmentsAt(pattern, path, 0, 0, make(map[[2]int]bool), make(map[[2]int]bool))
}

func matchPathSegmentsAt(pattern, path []string, pi, si int, seen, cache map[[2]int]bool) bool {
	key := [2]int{pi, si}
	if seen[key] {
		return cache[key]
	}
	seen[key] = true

	if pi == len(pattern) {
		cache[key] = si == len(path)
		return cache[key]
	}

	token := pattern[pi]
	if token == "**" {
		for next := si; next <= len(path); next++ {
			if matchPathSegmentsAt(pattern, path, pi+1, next, seen, cache) {
				cache[key] = true
				return true
			}
		}
		cache[key] = false
		return false
	}

	if si >= len(path) {
		cache[key] = false
		return false
	}

	cache[key] = matchSegment(token, path[si]) && matchPathSegmentsAt(pattern, path, pi+1, si+1, seen, cache)
	return cache[key]
}

func matchSegment(pattern, segment string) bool {
	if !strings.Contains(pattern, "*") {
		return pattern == segment
	}

	return matchSegmentAt(pattern, segment, 0, 0)
}

func matchSegmentAt(pattern, segment string, pi, si int) bool {
	for pi < len(pattern) {
		if pattern[pi] == '*' {
			for pi < len(pattern) && pattern[pi] == '*' {
				pi++
			}
			if pi == len(pattern) {
				return si < len(segment)
			}
			for next := si + 1; next <= len(segment); next++ {
				if matchSegmentAt(pattern, segment, pi, next) {
					return true
				}
			}
			return false
		}

		if si >= len(segment) || pattern[pi] != segment[si] {
			return false
		}
		pi++
		si++
	}

	return si == len(segment)
}
