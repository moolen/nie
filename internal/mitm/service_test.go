package mitm

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestService(t *testing.T) {
	t.Run("classifies SNI connections", func(t *testing.T) {
		handler := &capturingHandler{classified: make(chan ClassifiedConn, 1)}
		svc, err := NewService(ServiceConfig{ListenAddr: "127.0.0.1:0"}, ServiceDependencies{
			Handler: handler,
			OriginalDestination: func(net.Conn) (netip.AddrPort, error) {
				return netip.MustParseAddrPort("203.0.113.10:443"), nil
			},
			PeekClientHello: func(conn net.Conn) (BufferedConn, ClientHello, error) {
				return conn, ClientHello{ServerName: "api.github.com"}, nil
			},
		})
		if err != nil {
			t.Fatalf("NewService() error = %v", err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if err := svc.Start(ctx); err != nil {
			t.Fatalf("Start() error = %v", err)
		}
		defer svc.Stop(context.Background())

		clientConn, err := net.Dial("tcp", svc.listener.Addr().String())
		if err != nil {
			t.Fatalf("net.Dial() error = %v", err)
		}
		defer clientConn.Close()

		classified := waitForClassification(t, handler.classified)
		if classified.OriginalDestination != netip.MustParseAddrPort("203.0.113.10:443") {
			t.Fatalf("OriginalDestination = %s, want 203.0.113.10:443", classified.OriginalDestination)
		}
		if classified.ClientHello.ServerName != "api.github.com" {
			t.Fatalf("ClientHello.ServerName = %q, want api.github.com", classified.ClientHello.ServerName)
		}
		if classified.MissingSNI {
			t.Fatal("MissingSNI = true, want false")
		}
		_ = classified.Conn.Close()
	})

	t.Run("classifies missing SNI distinctly", func(t *testing.T) {
		handler := &capturingHandler{classified: make(chan ClassifiedConn, 1)}
		svc, err := NewService(ServiceConfig{ListenAddr: "127.0.0.1:0"}, ServiceDependencies{
			Handler: handler,
			OriginalDestination: func(net.Conn) (netip.AddrPort, error) {
				return netip.MustParseAddrPort("203.0.113.10:8443"), nil
			},
			PeekClientHello: func(conn net.Conn) (BufferedConn, ClientHello, error) {
				return conn, ClientHello{}, ErrClientHelloMissingSNI
			},
		})
		if err != nil {
			t.Fatalf("NewService() error = %v", err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if err := svc.Start(ctx); err != nil {
			t.Fatalf("Start() error = %v", err)
		}
		defer svc.Stop(context.Background())

		clientConn, err := net.Dial("tcp", svc.listener.Addr().String())
		if err != nil {
			t.Fatalf("net.Dial() error = %v", err)
		}
		defer clientConn.Close()

		classified := waitForClassification(t, handler.classified)
		if !classified.MissingSNI {
			t.Fatal("MissingSNI = false, want true")
		}
		if classified.ClientHello.ServerName != "" {
			t.Fatalf("ClientHello.ServerName = %q, want empty for missing SNI", classified.ClientHello.ServerName)
		}
		_ = classified.Conn.Close()
	})

	t.Run("stop closes stalled pre-classification connections", func(t *testing.T) {
		handler := &capturingHandler{classified: make(chan ClassifiedConn, 1)}
		svc, err := NewService(ServiceConfig{
			ListenAddr:         "127.0.0.1:0",
			ClientHelloTimeout: 5 * time.Second,
		}, ServiceDependencies{
			Handler: handler,
			OriginalDestination: func(net.Conn) (netip.AddrPort, error) {
				return netip.MustParseAddrPort("203.0.113.10:443"), nil
			},
			PeekClientHello: PeekClientHello,
		})
		if err != nil {
			t.Fatalf("NewService() error = %v", err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if err := svc.Start(ctx); err != nil {
			t.Fatalf("Start() error = %v", err)
		}

		clientConn, err := net.Dial("tcp", svc.listener.Addr().String())
		if err != nil {
			t.Fatalf("net.Dial() error = %v", err)
		}
		defer clientConn.Close()

		stopDone := make(chan error, 1)
		go func() {
			stopDone <- svc.Stop(context.Background())
		}()

		select {
		case err := <-stopDone:
			if err != nil {
				t.Fatalf("Stop() error = %v", err)
			}
		case <-time.After(500 * time.Millisecond):
			t.Fatal("Stop() blocked with stalled pre-classification connection")
		}
	})

	t.Run("drops idle clients after client hello timeout", func(t *testing.T) {
		handler := &capturingHandler{classified: make(chan ClassifiedConn, 1)}
		svc, err := NewService(ServiceConfig{
			ListenAddr:         "127.0.0.1:0",
			ClientHelloTimeout: 50 * time.Millisecond,
		}, ServiceDependencies{
			Handler: handler,
			OriginalDestination: func(net.Conn) (netip.AddrPort, error) {
				return netip.MustParseAddrPort("203.0.113.10:443"), nil
			},
			PeekClientHello: PeekClientHello,
		})
		if err != nil {
			t.Fatalf("NewService() error = %v", err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if err := svc.Start(ctx); err != nil {
			t.Fatalf("Start() error = %v", err)
		}
		defer svc.Stop(context.Background())

		clientConn, err := net.Dial("tcp", svc.listener.Addr().String())
		if err != nil {
			t.Fatalf("net.Dial() error = %v", err)
		}
		defer clientConn.Close()

		if err := clientConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			t.Fatalf("SetReadDeadline() error = %v", err)
		}
		_, err = clientConn.Read(make([]byte, 1))
		if err == nil {
			t.Fatal("client read error = nil, want closed idle connection")
		}
		if !errors.Is(err, io.EOF) && !isTimeoutish(err) {
			t.Fatalf("client read error = %v, want EOF or timeout", err)
		}

		select {
		case classified := <-handler.classified:
			t.Fatalf("unexpected classified connection: %+v", classified)
		case <-time.After(100 * time.Millisecond):
		}
	})
}

func waitForClassification(t *testing.T, classified <-chan ClassifiedConn) ClassifiedConn {
	t.Helper()

	select {
	case conn := <-classified:
		return conn
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for classified connection")
		return ClassifiedConn{}
	}
}

type capturingHandler struct {
	classified chan ClassifiedConn
}

func (h *capturingHandler) HandleClassifiedConnection(_ context.Context, conn ClassifiedConn) error {
	select {
	case h.classified <- conn:
		return nil
	default:
		return errors.New("classification channel is full")
	}
}

func isTimeoutish(err error) bool {
	type timeout interface {
		Timeout() bool
	}
	var t timeout
	return errors.As(err, &t) && t.Timeout()
}
