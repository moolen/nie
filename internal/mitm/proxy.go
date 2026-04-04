package mitm

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/moolen/nie/internal/config"
	"github.com/moolen/nie/internal/httppolicy"
	"github.com/moolen/nie/internal/policy"
)

var ErrHTTPSRequestDenied = errors.New("https request denied by policy")

type ProxyConfig struct {
	Mode             config.Mode
	MissingSNIAction httppolicy.Action
	DefaultAction    httppolicy.Action
}

type ProxyDependencies struct {
	Logger           *slog.Logger
	MITMPolicy       interface{ Evaluate(httppolicy.Request) (httppolicy.Decision, bool) }
	HostnamePolicy   interface{ Allows(string) bool }
	LeafCertificates interface{ CertificateForHost(string) (*tls.Certificate, error) }
	OpenUpstreamTLS  func(context.Context, string, netip.AddrPort) (net.Conn, error)
	OpenUpstreamTCP  func(context.Context, netip.AddrPort) (net.Conn, error)
}

type Proxy struct {
	mode             config.Mode
	missingSNIAction httppolicy.Action
	defaultAction    httppolicy.Action
	logger           *slog.Logger
	mitmPolicy       interface{ Evaluate(httppolicy.Request) (httppolicy.Decision, bool) }
	hostnamePolicy   interface{ Allows(string) bool }
	leafCertificates interface{ CertificateForHost(string) (*tls.Certificate, error) }
	openUpstreamTLS  func(context.Context, string, netip.AddrPort) (net.Conn, error)
	openUpstreamTCP  func(context.Context, netip.AddrPort) (net.Conn, error)
}

type denyAllHostnamePolicy struct{}

func (denyAllHostnamePolicy) Allows(string) bool { return false }

func NewProxy(cfg ProxyConfig, deps ProxyDependencies) (*Proxy, error) {
	if cfg.Mode != config.ModeEnforce && cfg.Mode != config.ModeAudit {
		return nil, fmt.Errorf("invalid mode %q", cfg.Mode)
	}
	if deps.LeafCertificates == nil {
		return nil, errors.New("leaf certificate cache must not be nil")
	}
	if deps.OpenUpstreamTLS == nil {
		return nil, errors.New("upstream tls opener must not be nil")
	}

	switch cfg.MissingSNIAction {
	case httppolicy.ActionDeny, httppolicy.ActionAudit:
	default:
		return nil, fmt.Errorf("invalid missing sni action %q", cfg.MissingSNIAction)
	}
	switch cfg.DefaultAction {
	case httppolicy.ActionDeny, httppolicy.ActionAudit:
	default:
		return nil, fmt.Errorf("invalid default action %q", cfg.DefaultAction)
	}

	logger := deps.Logger
	if logger == nil {
		logger = slog.Default()
	}
	hostnamePolicy := deps.HostnamePolicy
	if hostnamePolicy == nil {
		hostnamePolicy = denyAllHostnamePolicy{}
	}

	return &Proxy{
		mode:             cfg.Mode,
		missingSNIAction: cfg.MissingSNIAction,
		defaultAction:    cfg.DefaultAction,
		logger:           logger,
		mitmPolicy:       deps.MITMPolicy,
		hostnamePolicy:   hostnamePolicy,
		leafCertificates: deps.LeafCertificates,
		openUpstreamTLS:  deps.OpenUpstreamTLS,
		openUpstreamTCP:  deps.OpenUpstreamTCP,
	}, nil
}

func (p *Proxy) HandleClassifiedConnection(ctx context.Context, classified ClassifiedConn) error {
	if classified.Conn == nil {
		return errors.New("classified connection must not be nil")
	}
	defer classified.Conn.Close()

	host := policy.NormalizeHostname(classified.ClientHello.ServerName)
	if classified.MissingSNI || host == "" {
		return p.handleMissingSNI(ctx, classified)
	}

	leaf, err := p.leafCertificates.CertificateForHost(host)
	if err != nil {
		return fmt.Errorf("issue leaf certificate for %q: %w", host, err)
	}

	downstream := tls.Server(classified.Conn, &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		MinVersion:   tls.VersionTLS12,
	})
	defer downstream.Close()

	if err := downstream.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("complete downstream tls handshake for %q: %w", host, err)
	}

	reader := bufio.NewReader(downstream)
	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("read downstream http request for %q: %w", host, err)
		}

		action, matchedMITM := p.requestAction(host, classified.OriginalDestination.Port(), req)
		if !p.allowAction(action) {
			_ = req.Body.Close()
			return ErrHTTPSRequestDenied
		}
		if shouldLogAction(action, p.mode) {
			p.logWouldDeny(classified.OriginalDestination.Port(), host, req.Method, requestPath(req), action, matchedMITM)
		}

		upstream, err := p.openUpstreamTLS(ctx, host, classified.OriginalDestination)
		if err != nil {
			_ = req.Body.Close()
			return fmt.Errorf("open upstream tls connection for %q: %w", host, err)
		}

		if err := req.Write(upstream); err != nil {
			_ = req.Body.Close()
			_ = upstream.Close()
			return fmt.Errorf("forward upstream http request for %q: %w", host, err)
		}
		_ = req.Body.Close()

		resp, err := http.ReadResponse(bufio.NewReader(upstream), req)
		if err != nil {
			_ = upstream.Close()
			return fmt.Errorf("read upstream http response for %q: %w", host, err)
		}

		if err := resp.Write(downstream); err != nil {
			_ = resp.Body.Close()
			_ = upstream.Close()
			return fmt.Errorf("forward downstream http response for %q: %w", host, err)
		}

		_ = resp.Body.Close()
		_ = upstream.Close()
		if requestWantsClose(req) {
			return nil
		}
	}
}

func (p *Proxy) handleMissingSNI(ctx context.Context, classified ClassifiedConn) error {
	if p.mode == config.ModeAudit && p.missingSNIAction == httppolicy.ActionAudit {
		p.logger.Info("would_deny_https",
			"reason", "missing_sni",
			"dst", classified.OriginalDestination.String(),
		)
		if p.openUpstreamTCP != nil {
			return p.tunnelOpaqueTCP(ctx, classified.Conn, classified.OriginalDestination)
		}
	}
	return ErrHTTPSRequestDenied
}

func (p *Proxy) tunnelOpaqueTCP(ctx context.Context, downstream net.Conn, destination netip.AddrPort) error {
	upstream, err := p.openUpstreamTCP(ctx, destination)
	if err != nil {
		return fmt.Errorf("open upstream tcp connection: %w", err)
	}
	defer upstream.Close()

	copyErr := make(chan error, 2)
	go proxyStream(copyErr, upstream, downstream)
	go proxyStream(copyErr, downstream, upstream)

	var firstErr error
	for i := 0; i < 2; i++ {
		if err := <-copyErr; err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func proxyStream(done chan<- error, dst io.Writer, src io.Reader) {
	_, err := io.Copy(dst, src)
	done <- err
}

func (p *Proxy) requestAction(host string, port uint16, req *http.Request) (httppolicy.Action, bool) {
	if p.mitmPolicy != nil {
		if decision, matched := p.mitmPolicy.Evaluate(httppolicy.Request{
			Host:   host,
			Port:   port,
			Method: req.Method,
			Path:   requestPath(req),
		}); matched {
			return decision.Action, true
		}
	}

	if p.hostnamePolicy.Allows(host) {
		return httppolicy.ActionAllow, false
	}

	return p.defaultAction, false
}

func requestPath(req *http.Request) string {
	if req == nil || req.URL == nil {
		return "/"
	}
	if req.URL.Path == "" {
		return "/"
	}
	return req.URL.Path
}

func requestWantsClose(req *http.Request) bool {
	if req == nil {
		return false
	}
	return req.Close || strings.EqualFold(req.Header.Get("Connection"), "close")
}

func shouldLogAction(action httppolicy.Action, mode config.Mode) bool {
	return action == httppolicy.ActionAudit || (action == httppolicy.ActionDeny && mode == config.ModeAudit)
}

func (p *Proxy) allowAction(action httppolicy.Action) bool {
	switch action {
	case httppolicy.ActionAllow, httppolicy.ActionAudit:
		return true
	case httppolicy.ActionDeny:
		return p.mode == config.ModeAudit
	default:
		return false
	}
}

func (p *Proxy) logWouldDeny(port uint16, host, method, path string, action httppolicy.Action, matchedMITM bool) {
	reason := "https_default"
	if matchedMITM {
		reason = "https_mitm_rule"
	}
	p.logger.Info("would_deny_https",
		"reason", reason,
		"host", host,
		"port", port,
		"method", method,
		"path", path,
		"action", string(action),
	)
}
