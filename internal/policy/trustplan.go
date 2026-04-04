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
	allow      *Engine
	mitmByHost map[string][]uint16
}

func NewTrustPlan(allowPatterns []string, mitm []MITMHostPortRule) (*TrustPlan, error) {
	allowEngine, err := New(allowPatterns)
	if err != nil {
		return nil, err
	}

	portsByHost := make(map[string]map[uint16]struct{}, len(mitm))
	for i, rule := range mitm {
		host := NormalizeHostname(rule.Host)
		if host == "" {
			return nil, fmt.Errorf("mitm[%d].host must not be empty", i)
		}
		if !isValidHostname(host) {
			return nil, fmt.Errorf("mitm[%d].host %q is not a valid hostname", i, rule.Host)
		}
		if rule.Port == 0 {
			return nil, fmt.Errorf("mitm[%d].port must be a positive non-zero value", i)
		}

		if _, exists := portsByHost[host]; !exists {
			portsByHost[host] = map[uint16]struct{}{}
		}
		portsByHost[host][rule.Port] = struct{}{}
	}

	compiled := make(map[string][]uint16, len(portsByHost))
	for host, portsSet := range portsByHost {
		ports := make([]uint16, 0, len(portsSet))
		for port := range portsSet {
			ports = append(ports, port)
		}
		sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
		compiled[host] = ports
	}

	return &TrustPlan{
		allow:      allowEngine,
		mitmByHost: compiled,
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
	ports, ok := p.mitmByHost[host]
	if !ok {
		return nil, false
	}

	out := make([]uint16, len(ports))
	copy(out, ports)
	return out, true
}
