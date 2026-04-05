package app

import (
	"errors"
	"fmt"
	"net"
)

func validateProtectedInterface(iface string) error {
	netIf, err := net.InterfaceByName(iface)
	if err != nil {
		return fmt.Errorf("lookup interface %q: %w", iface, err)
	}
	addrs, err := netIf.Addrs()
	if err != nil {
		return fmt.Errorf("list interface %q addresses: %w", iface, err)
	}
	return validateProtectedInterfaceAddrs(iface, addrs)
}

func validateProtectedInterfaceAddrs(iface string, addrs []net.Addr) error {
	for _, addr := range addrs {
		ip, err := addrIP(addr)
		if err != nil {
			return fmt.Errorf("parse address %q on interface %q: %w", addr.String(), iface, err)
		}
		if ip == nil || ip.IsUnspecified() || ip.To4() != nil {
			continue
		}
		return fmt.Errorf("interface %s has IPv6 addresses assigned (%s); nie is IPv4-only and refuses to start", iface, addr.String())
	}
	return nil
}

func addrIP(addr net.Addr) (net.IP, error) {
	switch v := addr.(type) {
	case *net.IPNet:
		return v.IP, nil
	case *net.IPAddr:
		return v.IP, nil
	default:
		return nil, errors.New("unsupported address type")
	}
}
