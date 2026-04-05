//go:build linux

package trustsync

import (
	"net"
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

func TestHasActiveTCPFlowIgnoresTimeWaitState(t *testing.T) {
	dst := mustDestinationWithProtocol(t, "203.0.113.10", 443, ProtocolTCP)
	inspector := &netlinkConntrackInspector{
		listFlows: func(netlink.ConntrackTableType, netlink.InetFamily) ([]*netlink.ConntrackFlow, error) {
			return []*netlink.ConntrackFlow{
				{
					Forward: netlink.IPTuple{
						Protocol: uint8(ProtocolTCP),
						DstIP:    net.ParseIP("203.0.113.10").To4(),
						DstPort:  443,
					},
					ProtoInfo: &netlink.ProtoInfoTCP{State: nl.TCP_CONNTRACK_TIME_WAIT},
				},
			}, nil
		},
	}

	active, err := inspector.HasActiveTCPFlow(dst)
	if err != nil {
		t.Fatalf("HasActiveTCPFlow() error = %v", err)
	}
	if active {
		t.Fatal("HasActiveTCPFlow() = true, want false for TIME_WAIT")
	}
}

func TestHasActiveTCPFlowTreatsEstablishedStateAsActive(t *testing.T) {
	dst := mustDestinationWithProtocol(t, "203.0.113.11", 443, ProtocolTCP)
	inspector := &netlinkConntrackInspector{
		listFlows: func(netlink.ConntrackTableType, netlink.InetFamily) ([]*netlink.ConntrackFlow, error) {
			return []*netlink.ConntrackFlow{
				{
					Forward: netlink.IPTuple{
						Protocol: uint8(ProtocolTCP),
						DstIP:    net.ParseIP("203.0.113.11").To4(),
						DstPort:  443,
					},
					ProtoInfo: &netlink.ProtoInfoTCP{State: nl.TCP_CONNTRACK_ESTABLISHED},
				},
			}, nil
		},
	}

	active, err := inspector.HasActiveTCPFlow(dst)
	if err != nil {
		t.Fatalf("HasActiveTCPFlow() error = %v", err)
	}
	if !active {
		t.Fatal("HasActiveTCPFlow() = false, want true for ESTABLISHED")
	}
}
