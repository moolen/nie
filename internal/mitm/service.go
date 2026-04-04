package mitm

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
)

type ServiceConfig struct {
	ListenAddr string
}

type ClassifiedConn struct {
	Conn                BufferedConn
	OriginalDestination netip.AddrPort
	ClientHello         ClientHello
	MissingSNI          bool
}

type ClassifiedConnHandler interface {
	HandleClassifiedConnection(context.Context, ClassifiedConn) error
}

type ServiceDependencies struct {
	Listen              func(network, address string) (net.Listener, error)
	OriginalDestination func(net.Conn) (netip.AddrPort, error)
	PeekClientHello     func(net.Conn) (BufferedConn, ClientHello, error)
	Handler             ClassifiedConnHandler
}

type Service struct {
	listenAddr          string
	listen              func(network, address string) (net.Listener, error)
	originalDestination func(net.Conn) (netip.AddrPort, error)
	peekClientHello     func(net.Conn) (BufferedConn, ClientHello, error)
	handler             ClassifiedConnHandler

	mu       sync.Mutex
	listener net.Listener
	started  bool
	wg       sync.WaitGroup
}

func NewService(cfg ServiceConfig, deps ServiceDependencies) (*Service, error) {
	listenAddr := strings.TrimSpace(cfg.ListenAddr)
	if listenAddr == "" {
		return nil, errors.New("https listen address must not be empty")
	}
	if deps.Handler == nil {
		return nil, errors.New("classified connection handler must not be nil")
	}
	if deps.Listen == nil {
		deps.Listen = net.Listen
	}
	if deps.OriginalDestination == nil {
		deps.OriginalDestination = OriginalDestination
	}
	if deps.PeekClientHello == nil {
		deps.PeekClientHello = PeekClientHello
	}

	return &Service{
		listenAddr:          listenAddr,
		listen:              deps.Listen,
		originalDestination: deps.OriginalDestination,
		peekClientHello:     deps.PeekClientHello,
		handler:             deps.Handler,
	}, nil
}

func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.started {
		return nil
	}

	listener, err := s.listen("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", s.listenAddr, err)
	}

	s.listener = listener
	s.started = true
	s.wg.Add(1)
	go s.acceptLoop(context.WithoutCancel(ctx), listener)
	return nil
}

func (s *Service) Stop(context.Context) error {
	s.mu.Lock()
	if !s.started {
		s.mu.Unlock()
		return nil
	}

	listener := s.listener
	s.listener = nil
	s.started = false
	s.mu.Unlock()

	closeErr := listener.Close()
	s.wg.Wait()
	if closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
		return fmt.Errorf("close https listener: %w", closeErr)
	}
	return nil
}

func (s *Service) acceptLoop(ctx context.Context, listener net.Listener) {
	defer s.wg.Done()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Temporary() {
				continue
			}
			return
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConn(ctx, conn)
		}()
	}
}

func (s *Service) handleConn(ctx context.Context, conn net.Conn) {
	originalDestination, err := s.originalDestination(conn)
	if err != nil {
		_ = conn.Close()
		return
	}

	buffered, hello, err := s.peekClientHello(conn)
	if buffered == nil {
		buffered = &bufferedConn{Conn: conn, reader: nil}
	}
	if err != nil && !errors.Is(err, ErrClientHelloMissingSNI) {
		_ = buffered.Close()
		return
	}

	classified := ClassifiedConn{
		Conn:                buffered,
		OriginalDestination: originalDestination,
		ClientHello:         hello,
		MissingSNI:          errors.Is(err, ErrClientHelloMissingSNI),
	}
	if err := s.handler.HandleClassifiedConnection(ctx, classified); err != nil {
		_ = classified.Conn.Close()
	}
}
