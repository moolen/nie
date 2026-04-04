package policy

import (
	"fmt"
	"sort"
)

type MITMHostPortRule struct {
	Host string
	Port uint16
}

type TrustPlan struct {
	allow *Engine
	mitm  []mitmPatternPorts
}

type mitmPatternPorts struct {
	engine *Engine
	ports  []uint16
}

func NewTrustPlan(allowPatterns []string, mitm []MITMHostPortRule) (*TrustPlan, error) {
	allowEngine, err := New(allowPatterns)
	if err != nil {
		return nil, err
	}

	portsByHost := make(map[string]map[uint16]struct{}, len(mitm))
	patternEngines := make(map[string]*Engine, len(mitm))
	for i, rule := range mitm {
		pattern := NormalizeHostname(rule.Host)
		if pattern == "" {
			return nil, fmt.Errorf("mitm[%d].host must not be empty", i)
		}
		if _, exists := patternEngines[pattern]; !exists {
			engine, err := New([]string{rule.Host})
			if err != nil {
				return nil, fmt.Errorf("mitm[%d].host %q is invalid: %w", i, rule.Host, err)
			}
			patternEngines[pattern] = engine
		}
		if rule.Port == 0 {
			return nil, fmt.Errorf("mitm[%d].port must be a positive non-zero value", i)
		}

		if _, exists := portsByHost[pattern]; !exists {
			portsByHost[pattern] = map[uint16]struct{}{}
		}
		portsByHost[pattern][rule.Port] = struct{}{}
	}

	patterns := make([]string, 0, len(portsByHost))
	for pattern := range portsByHost {
		patterns = append(patterns, pattern)
	}
	sort.Strings(patterns)

	matching := make([]mitmPatternPorts, 0, len(portsByHost))
	for _, pattern := range patterns {
		portsSet := portsByHost[pattern]
		ports := make([]uint16, 0, len(portsSet))
		for port := range portsSet {
			ports = append(ports, port)
		}
		sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
		matching = append(matching, mitmPatternPorts{
			engine: patternEngines[pattern],
			ports:  ports,
		})
	}

	return &TrustPlan{
		allow: allowEngine,
		mitm:  matching,
	}, nil
}

func (p *TrustPlan) PortsForHost(host string) ([]uint16, bool) {
	host = NormalizeHostname(host)
	if host == "" || !isValidHostname(host) {
		return nil, false
	}

	if p.allow.Allows(host) {
		return []uint16{0}, true
	}
	portsSet := map[uint16]struct{}{}
	for _, rule := range p.mitm {
		if !rule.engine.Allows(host) {
			continue
		}
		for _, port := range rule.ports {
			portsSet[port] = struct{}{}
		}
	}
	if len(portsSet) == 0 {
		return nil, false
	}

	out := make([]uint16, 0, len(portsSet))
	for port := range portsSet {
		out = append(out, port)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, true
}
