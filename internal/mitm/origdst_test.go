//go:build linux

package mitm

import (
	"net/netip"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestOriginalDestinationFromSockaddr(t *testing.T) {
	sockaddr := unix.RawSockaddrInet4{
		Family: unix.AF_INET,
		Addr:   [4]byte{203, 0, 113, 10},
	}
	portBytes := (*[2]byte)(unsafe.Pointer(&sockaddr.Port))
	portBytes[0] = 0x01
	portBytes[1] = 0xbb

	got, err := originalDestinationFromSockaddr(sockaddr)
	if err != nil {
		t.Fatalf("originalDestinationFromSockaddr() error = %v", err)
	}

	want := netip.MustParseAddrPort("203.0.113.10:443")
	if got != want {
		t.Fatalf("original destination = %s, want %s", got, want)
	}
}
