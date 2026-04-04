//go:build !linux

package mitm

import (
	"errors"
	"net"
	"net/netip"
)

func OriginalDestination(conn net.Conn) (netip.AddrPort, error) {
	if conn == nil {
		return netip.AddrPort{}, errors.New("connection must not be nil")
	}
	return netip.AddrPort{}, errors.New("original destination lookup is only supported on linux")
}
