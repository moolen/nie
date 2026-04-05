package policy

import "testing"

func TestTrustPlan_PortsForMITMOnlyHost(t *testing.T) {
	plan, err := NewTrustPlan([]string{"github.com"}, []uint16{443, 8443}, []MITMHostPortRule{
		{Host: "api.github.com", Port: 443},
	})
	if err != nil {
		t.Fatalf("NewTrustPlan() error = %v", err)
	}

	ports, ok := plan.PortsForHost("api.github.com")
	if !ok || len(ports) != 1 || ports[0] != 443 {
		t.Fatalf("PortsForHost(api.github.com) = %v, %v; want [443], true", ports, ok)
	}
}

func TestTrustPlan_PortsForHost_ReturnsConfiguredAllowPorts(t *testing.T) {
	plan, err := NewTrustPlan([]string{"github.com"}, []uint16{8443, 443, 8443}, nil)
	if err != nil {
		t.Fatalf("NewTrustPlan() error = %v", err)
	}

	ports, ok := plan.PortsForHost("github.com")
	if !ok || len(ports) != 2 || ports[0] != 443 || ports[1] != 8443 {
		t.Fatalf("PortsForHost(github.com) = %v, %v; want [443 8443], true", ports, ok)
	}
}

func TestTrustPlan_PortsForHost_AllowedHostUnionsAllowAndMITMPorts(t *testing.T) {
	plan, err := NewTrustPlan([]string{"github.com"}, []uint16{8443, 443}, []MITMHostPortRule{
		{Host: "github.com", Port: 9443},
		{Host: "github.com", Port: 443},
	})
	if err != nil {
		t.Fatalf("NewTrustPlan() error = %v", err)
	}

	ports, ok := plan.PortsForHost("github.com")
	if !ok || len(ports) != 3 || ports[0] != 443 || ports[1] != 8443 || ports[2] != 9443 {
		t.Fatalf("PortsForHost(github.com) = %v, %v; want [443 8443 9443], true", ports, ok)
	}
}

func TestTrustPlan_PortsForHost_ReturnsSortedUniqueMITMPorts(t *testing.T) {
	plan, err := NewTrustPlan(nil, nil, []MITMHostPortRule{
		{Host: "api.github.com", Port: 8443},
		{Host: "api.github.com", Port: 443},
		{Host: "api.github.com", Port: 8443},
	})
	if err != nil {
		t.Fatalf("NewTrustPlan() error = %v", err)
	}

	ports, ok := plan.PortsForHost("api.github.com")
	if !ok || len(ports) != 2 || ports[0] != 443 || ports[1] != 8443 {
		t.Fatalf("PortsForHost(api.github.com) = %v, %v; want [443 8443], true", ports, ok)
	}
}

func TestTrustPlan_PortsForHost_MatchesWildcardMITMPattern(t *testing.T) {
	plan, err := NewTrustPlan(nil, nil, []MITMHostPortRule{
		{Host: "*.github.com", Port: 443},
	})
	if err != nil {
		t.Fatalf("NewTrustPlan() error = %v", err)
	}

	ports, ok := plan.PortsForHost("api.github.com")
	if !ok || len(ports) != 1 || ports[0] != 443 {
		t.Fatalf("PortsForHost(api.github.com) = %v, %v; want [443], true", ports, ok)
	}
}

func TestTrustPlan_PortsForHost_UnionsPortsFromOverlappingMITMPatterns(t *testing.T) {
	plan, err := NewTrustPlan(nil, nil, []MITMHostPortRule{
		{Host: "*.github.com", Port: 443},
		{Host: "api.github.com", Port: 8443},
		{Host: "**.github.com", Port: 9443},
	})
	if err != nil {
		t.Fatalf("NewTrustPlan() error = %v", err)
	}

	ports, ok := plan.PortsForHost("api.github.com")
	if !ok || len(ports) != 3 || ports[0] != 443 || ports[1] != 8443 || ports[2] != 9443 {
		t.Fatalf("PortsForHost(api.github.com) = %v, %v; want [443 8443 9443], true", ports, ok)
	}
}
