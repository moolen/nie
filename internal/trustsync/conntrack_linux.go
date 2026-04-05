//go:build linux

package trustsync

import (
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type netlinkConntrackInspector struct {
	listFlows func(table netlink.ConntrackTableType, family netlink.InetFamily) ([]*netlink.ConntrackFlow, error)
}

func newConntrackInspector() ConntrackInspector {
	return &netlinkConntrackInspector{
		listFlows: netlink.ConntrackTableList,
	}
}

func (i *netlinkConntrackInspector) HasActiveTCPFlow(dst Destination) (bool, error) {
	family, ok := conntrackFamilyForDestination(dst)
	if !ok {
		return false, nil
	}

	flows, err := i.listFlows(netlink.ConntrackTable, family)
	if err != nil {
		return false, err
	}

	for _, flow := range flows {
		if flow == nil {
			continue
		}
		if flow.Forward.Protocol != uint8(ProtocolTCP) && flow.Reverse.Protocol != uint8(ProtocolTCP) {
			continue
		}
		if tupleMatchesDestination(flow.Forward.DstIP, flow.Forward.DstPort, dst) {
			return true, nil
		}
		if tupleMatchesDestination(flow.Reverse.SrcIP, flow.Reverse.SrcPort, dst) {
			return true, nil
		}
	}

	return false, nil
}

func conntrackFamilyForDestination(dst Destination) (netlink.InetFamily, bool) {
	if dst.IP.Is4() {
		return netlink.InetFamily(unix.AF_INET), true
	}
	if dst.IP.Is6() {
		return netlink.InetFamily(unix.AF_INET6), true
	}
	return 0, false
}

func tupleMatchesDestination(rawIP net.IP, port uint16, dst Destination) bool {
	tupleIP, ok := netip.AddrFromSlice(rawIP)
	if !ok {
		return false
	}
	return tupleIP.Unmap() == dst.IP.Unmap() && port == dst.Port
}
