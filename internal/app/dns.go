package app

import (
	"context"
	"net"

	"github.com/miekg/dns"

	"github.com/moolen/nie/internal/runtime"
)

type dnsServer interface {
	ActivateAndServe() error
	ShutdownContext(context.Context) error
}

type dnsListenerLifecycle struct {
	addr    string
	handler dns.Handler

	udp dnsServer
	tcp dnsServer
}

func (d *dnsListenerLifecycle) Start(context.Context) error {
	pc, err := net.ListenPacket("udp", d.addr)
	if err != nil {
		return err
	}

	ln, err := net.Listen("tcp", d.addr)
	if err != nil {
		_ = pc.Close()
		return err
	}

	d.udp = &dns.Server{PacketConn: pc, Handler: d.handler}
	d.tcp = &dns.Server{Listener: ln, Handler: d.handler}

	go func() { _ = d.udp.ActivateAndServe() }()
	go func() { _ = d.tcp.ActivateAndServe() }()
	return nil
}

func (d *dnsListenerLifecycle) Stop(ctx context.Context) error {
	var firstErr error

	if d.tcp != nil {
		if err := d.tcp.ShutdownContext(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if d.udp != nil {
		if err := d.udp.ShutdownContext(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

type dnsClientUpstream struct {
	addrs  []string
	dialer *net.Dialer
}

func (u dnsClientUpstream) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	c := &dns.Client{Dialer: u.dialer}
	var firstErr error
	for _, addr := range u.addrs {
		resp, _, err := c.ExchangeContext(ctx, req, addr)
		if err == nil && resp != nil {
			return resp, nil
		}
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return nil, firstErr
}

var _ runtime.Lifecycle = (*dnsListenerLifecycle)(nil)
