//go:build linux

package mitm

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

func OriginalDestination(conn net.Conn) (netip.AddrPort, error) {
	syscallConn, ok := conn.(syscall.Conn)
	if !ok {
		return netip.AddrPort{}, errors.New("connection does not expose syscall.Conn")
	}

	rawConn, err := syscallConn.SyscallConn()
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("extract syscall conn: %w", err)
	}

	var (
		sockaddr   unix.RawSockaddrInet4
		controlErr error
	)
	if err := rawConn.Control(func(fd uintptr) {
		sockaddr, controlErr = originalDestinationSockaddr(int(fd))
	}); err != nil {
		return netip.AddrPort{}, fmt.Errorf("run original destination lookup: %w", err)
	}
	if controlErr != nil {
		return netip.AddrPort{}, controlErr
	}

	return originalDestinationFromSockaddr(sockaddr)
}

func originalDestinationSockaddr(fd int) (unix.RawSockaddrInet4, error) {
	var sockaddr unix.RawSockaddrInet4
	size := uint32(unsafe.Sizeof(sockaddr))

	_, _, errno := unix.Syscall6(
		unix.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(unix.SOL_IP),
		uintptr(unix.SO_ORIGINAL_DST),
		uintptr(unsafe.Pointer(&sockaddr)),
		uintptr(unsafe.Pointer(&size)),
		0,
	)
	if errno != 0 {
		return unix.RawSockaddrInet4{}, fmt.Errorf("read SO_ORIGINAL_DST: %w", errno)
	}

	return sockaddr, nil
}

func originalDestinationFromSockaddr(sockaddr unix.RawSockaddrInet4) (netip.AddrPort, error) {
	if sockaddr.Family != unix.AF_INET {
		return netip.AddrPort{}, fmt.Errorf("unsupported sockaddr family %d", sockaddr.Family)
	}

	portBytes := (*[2]byte)(unsafe.Pointer(&sockaddr.Port))
	port := binary.BigEndian.Uint16(portBytes[:])

	addr, ok := netip.AddrFromSlice(sockaddr.Addr[:])
	if !ok {
		return netip.AddrPort{}, errors.New("invalid original destination address")
	}
	return netip.AddrPortFrom(addr, port), nil
}
