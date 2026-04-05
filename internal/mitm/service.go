package mitm

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

type ServiceConfig struct {
	ListenAddr          string
	ClientHelloTimeout  time.Duration
	ClientHelloMaxBytes int
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
	clientHelloTimeout  time.Duration
	listen              func(network, address string) (net.Listener, error)
	originalDestination func(net.Conn) (netip.AddrPort, error)
	peekClientHello     func(net.Conn) (BufferedConn, ClientHello, error)
	handler             ClassifiedConnHandler

	mu       sync.Mutex
	listener net.Listener
	started  bool
	active   map[net.Conn]struct{}
	wg       sync.WaitGroup
}

const defaultClientHelloTimeout = 5 * time.Second

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
	clientHelloMaxBytes := cfg.ClientHelloMaxBytes
	if clientHelloMaxBytes <= 0 {
		clientHelloMaxBytes = defaultClientHelloMaxBytes
	}
	if deps.PeekClientHello == nil {
		deps.PeekClientHello = func(conn net.Conn) (BufferedConn, ClientHello, error) {
			return PeekClientHelloWithLimit(conn, clientHelloMaxBytes)
		}
	}
	clientHelloTimeout := cfg.ClientHelloTimeout
	if clientHelloTimeout <= 0 {
		clientHelloTimeout = defaultClientHelloTimeout
	}

	return &Service{
		listenAddr:          listenAddr,
		clientHelloTimeout:  clientHelloTimeout,
		listen:              deps.Listen,
		originalDestination: deps.OriginalDestination,
		peekClientHello:     deps.PeekClientHello,
		handler:             deps.Handler,
		active:              make(map[net.Conn]struct{}),
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
	active := s.activeConnections()
	for _, conn := range active {
		_ = conn.Close()
	}
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
		if !s.trackConn(conn) {
			_ = conn.Close()
			return
		}

		s.wg.Add(1)
		go func(conn net.Conn) {
			defer s.wg.Done()
			defer s.untrackConn(conn)
			s.handleConn(ctx, conn)
		}(conn)
	}
}

func (s *Service) handleConn(ctx context.Context, conn net.Conn) {
	if s.clientHelloTimeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(s.clientHelloTimeout))
	}
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
	_ = conn.SetDeadline(time.Time{})
	if err := s.handler.HandleClassifiedConnection(ctx, classified); err != nil {
		_ = classified.Conn.Close()
	}
}

func (s *Service) trackConn(conn net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.started {
		return false
	}
	s.active[conn] = struct{}{}
	return true
}

func (s *Service) untrackConn(conn net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.active, conn)
}

func (s *Service) activeConnections() []net.Conn {
	s.mu.Lock()
	defer s.mu.Unlock()

	conns := make([]net.Conn, 0, len(s.active))
	for conn := range s.active {
		conns = append(conns, conn)
	}
	return conns
}
