//go:build !linux

package netx

import (
	"errors"
	"net"
)

func NewMarkedDialer(mark uint32) (*net.Dialer, error) {
	if mark == 0 {
		return nil, errors.New("socket mark must be a positive non-zero value")
	}
	return nil, errors.New("marked outbound dialing is only supported on linux")
}
