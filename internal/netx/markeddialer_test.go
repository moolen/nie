//go:build linux

package netx

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestMarkedDialer_ControlSetsSO_MARK(t *testing.T) {
	dialer, err := NewMarkedDialer(4242)
	if err != nil {
		t.Fatalf("NewMarkedDialer() error = %v", err)
	}
	if dialer.Control == nil {
		t.Fatal("Dialer.Control = nil, want socket control hook")
	}

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("unix.Socket() error = %v", err)
	}
	defer unix.Close(fd)

	rawConn := testRawConn(func(fn func(fd uintptr)) error {
		fn(uintptr(fd))
		return nil
	})
	if err := dialer.Control("tcp4", "203.0.113.10:443", rawConn); err != nil {
		t.Fatalf("Dialer.Control() error = %v", err)
	}

	got, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK)
	if err != nil {
		t.Fatalf("unix.GetsockoptInt(SO_MARK) error = %v", err)
	}
	if got != 4242 {
		t.Fatalf("socket mark = %d, want 4242", got)
	}
}

type testRawConn func(func(fd uintptr)) error

func (r testRawConn) Control(fn func(fd uintptr)) error {
	return r(fn)
}

func (r testRawConn) Read(func(fd uintptr) (done bool)) error {
	return nil
}

func (r testRawConn) Write(func(fd uintptr) (done bool)) error {
	return nil
}
