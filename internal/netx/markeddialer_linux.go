//go:build linux

package netx

import (
	"errors"
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func NewMarkedDialer(mark uint32) (*net.Dialer, error) {
	if mark == 0 {
		return nil, errors.New("socket mark must be a positive non-zero value")
	}

	return &net.Dialer{
		Control: func(network, address string, c syscall.RawConn) error {
			var controlErr error
			if err := c.Control(func(fd uintptr) {
				controlErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark))
			}); err != nil {
				return fmt.Errorf("run socket control hook for %s %s: %w", network, address, err)
			}
			if controlErr != nil {
				return fmt.Errorf("set SO_MARK for %s %s: %w", network, address, controlErr)
			}
			return nil
		},
	}, nil
}
