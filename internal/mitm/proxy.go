package mitm

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/moolen/nie/internal/config"
	"github.com/moolen/nie/internal/httppolicy"
	"github.com/moolen/nie/internal/policy"
	"golang.org/x/net/http2"
)

var ErrHTTPSRequestDenied = errors.New("https request denied by policy")
var ErrHTTPSRequestHeadersTooLarge = errors.New("https request headers exceed configured limit")

const (
	defaultProxyIdleTimeout    = 30 * time.Second
	defaultProxyMaxHeaderBytes = 1 << 20
)

type ProxyConfig struct {
	Mode             config.Mode
	MissingSNIAction httppolicy.Action
	DefaultAction    httppolicy.Action
	IdleTimeout      time.Duration
	MaxHeaderBytes   int
}

type ProxyDependencies struct {
	Logger     *slog.Logger
	MITMPolicy interface {
		Evaluate(httppolicy.Request) (httppolicy.Decision, bool)
	}
	HostnamePolicy   interface{ Allows(string) bool }
	LeafCertificates interface {
		CertificateForHost(string) (*tls.Certificate, error)
	}
	OpenUpstreamTLS      func(context.Context, string, netip.AddrPort) (net.Conn, error)
	OpenUpstreamHTTP1TLS func(context.Context, string, netip.AddrPort) (net.Conn, error)
	OpenUpstreamHTTP2TLS func(context.Context, string, netip.AddrPort) (net.Conn, error)
	OpenUpstreamTCP      func(context.Context, netip.AddrPort) (net.Conn, error)
}

type Proxy struct {
	mode             config.Mode
	missingSNIAction httppolicy.Action
	defaultAction    httppolicy.Action
	logger           *slog.Logger
	mitmPolicy       interface {
		Evaluate(httppolicy.Request) (httppolicy.Decision, bool)
	}
	hostnamePolicy   interface{ Allows(string) bool }
	leafCertificates interface {
		CertificateForHost(string) (*tls.Certificate, error)
	}
	openUpstreamHTTP1TLS func(context.Context, string, netip.AddrPort) (net.Conn, error)
	openUpstreamHTTP2TLS func(context.Context, string, netip.AddrPort) (net.Conn, error)
	openUpstreamTCP      func(context.Context, netip.AddrPort) (net.Conn, error)
	idleTimeout          time.Duration
	maxHeaderBytes       int
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
		if deps.OpenUpstreamHTTP1TLS == nil || deps.OpenUpstreamHTTP2TLS == nil {
			return nil, errors.New("upstream tls opener must not be nil")
		}
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

	idleTimeout := cfg.IdleTimeout
	if idleTimeout <= 0 {
		idleTimeout = defaultProxyIdleTimeout
	}
	maxHeaderBytes := cfg.MaxHeaderBytes
	if maxHeaderBytes <= 0 {
		maxHeaderBytes = defaultProxyMaxHeaderBytes
	}

	logger := deps.Logger
	if logger == nil {
		logger = slog.Default()
	}
	hostnamePolicy := deps.HostnamePolicy
	if hostnamePolicy == nil {
		hostnamePolicy = denyAllHostnamePolicy{}
	}

	openUpstreamHTTP1TLS := deps.OpenUpstreamHTTP1TLS
	openUpstreamHTTP2TLS := deps.OpenUpstreamHTTP2TLS
	if deps.OpenUpstreamTLS != nil {
		if openUpstreamHTTP1TLS == nil {
			openUpstreamHTTP1TLS = deps.OpenUpstreamTLS
		}
		if openUpstreamHTTP2TLS == nil {
			openUpstreamHTTP2TLS = deps.OpenUpstreamTLS
		}
	}

	return &Proxy{
		mode:                 cfg.Mode,
		missingSNIAction:     cfg.MissingSNIAction,
		defaultAction:        cfg.DefaultAction,
		logger:               logger,
		mitmPolicy:           deps.MITMPolicy,
		hostnamePolicy:       hostnamePolicy,
		leafCertificates:     deps.LeafCertificates,
		openUpstreamHTTP1TLS: openUpstreamHTTP1TLS,
		openUpstreamHTTP2TLS: openUpstreamHTTP2TLS,
		openUpstreamTCP:      deps.OpenUpstreamTCP,
		idleTimeout:          idleTimeout,
		maxHeaderBytes:       maxHeaderBytes,
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

	downstreamTLS := tls.Server(withIdleTimeout(classified.Conn, p.idleTimeout), &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
	})
	defer downstreamTLS.Close()

	if err := downstreamTLS.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("complete downstream tls handshake for %q: %w", host, err)
	}
	downstream := withIdleTimeout(downstreamTLS, p.idleTimeout)
	if downstreamTLS.ConnectionState().NegotiatedProtocol == "h2" {
		return p.handleHTTP2Connection(ctx, downstream, host, classified.OriginalDestination)
	}
	return p.handleHTTP1Connection(ctx, downstream, host, classified.OriginalDestination)
}

func (p *Proxy) handleHTTP1Connection(ctx context.Context, downstream net.Conn, host string, destination netip.AddrPort) error {
	reader := bufio.NewReaderSize(downstream, p.readerBufferSize())
	var (
		upstream       net.Conn
		upstreamReader *bufio.Reader
		h2Upstream     *http2.ClientConn
	)
	defer func() {
		if upstream != nil {
			_ = upstream.Close()
		}
	}()
	defer func() {
		if h2Upstream != nil {
			_ = h2Upstream.Close()
		}
	}()

	for {
		if err := ensureHeaderLimit(reader, p.maxHeaderBytes); err != nil {
			if isBenignReadTermination(err) {
				return nil
			}
			return fmt.Errorf("read downstream http request for %q: %w", host, err)
		}
		req, err := http.ReadRequest(reader)
		if err != nil {
			if isBenignReadTermination(err) {
				return nil
			}
			return fmt.Errorf("read downstream http request for %q: %w", host, err)
		}
		if mismatch, authority := requestAuthorityMismatch(host, req); mismatch {
			if p.mode == config.ModeAudit {
				p.logAuthorityMismatch(destination.Port(), host, authority, req.Method, requestPath(req))
			} else {
				_ = req.Body.Close()
				return ErrHTTPSRequestDenied
			}
		}

		action, matchedMITM := p.requestAction(host, destination.Port(), req)
		if !p.allowAction(action) {
			_ = req.Body.Close()
			return ErrHTTPSRequestDenied
		}
		if shouldLogAction(action, p.mode) {
			p.logWouldDeny(destination.Port(), host, req.Method, requestPath(req), action, matchedMITM)
		}
		closeAfterRequest := requestWantsClose(req)

		if upstream == nil && h2Upstream == nil {
			rawUpstream, err := p.openUpstreamHTTP1TLS(ctx, host, destination)
			if err != nil {
				_ = req.Body.Close()
				return fmt.Errorf("open upstream tls connection for %q: %w", host, err)
			}
			if negotiatedProtocol(rawUpstream) == "h2" {
				transport := &http2.Transport{}
				h2Upstream, err = transport.NewClientConn(withIdleTimeout(rawUpstream, p.idleTimeout))
				if err != nil {
					_ = req.Body.Close()
					_ = rawUpstream.Close()
					return fmt.Errorf("initialize upstream http2 client for %q: %w", host, err)
				}
			} else {
				upstream = withIdleTimeout(rawUpstream, p.idleTimeout)
				upstreamReader = bufio.NewReaderSize(upstream, p.readerBufferSize())
			}
		}
		_ = req.Body.Close()

		if h2Upstream != nil {
			upstreamReq := req.Clone(req.Context())
			upstreamReq.RequestURI = ""
			upstreamReq.URL = cloneUpstreamURL(req.URL, host)
			upstreamReq.Host = req.Host

			resp, err := h2Upstream.RoundTrip(upstreamReq)
			if err != nil {
				return fmt.Errorf("round trip upstream http2 request for %q: %w", host, err)
			}
			if err := resp.Write(downstream); err != nil {
				_ = resp.Body.Close()
				return fmt.Errorf("forward downstream http response for %q: %w", host, err)
			}
			_ = resp.Body.Close()
			if closeAfterRequest {
				return nil
			}
			continue
		}

		if err := req.Write(upstream); err != nil {
			_ = upstream.Close()
			upstream = nil
			upstreamReader = nil
			return fmt.Errorf("forward upstream http request for %q: %w", host, err)
		}

		resp, err := http.ReadResponse(upstreamReader, req)
		if err != nil {
			_ = upstream.Close()
			upstream = nil
			upstreamReader = nil
			return fmt.Errorf("read upstream http response for %q: %w", host, err)
		}

		if err := resp.Write(downstream); err != nil {
			_ = resp.Body.Close()
			_ = upstream.Close()
			upstream = nil
			upstreamReader = nil
			return fmt.Errorf("forward downstream http response for %q: %w", host, err)
		}

		closeUpstream := responseWantsClose(resp)
		_ = resp.Body.Close()
		if closeUpstream {
			_ = upstream.Close()
			upstream = nil
			upstreamReader = nil
		}
		if closeAfterRequest {
			return nil
		}
	}
}

func (p *Proxy) handleHTTP2Connection(ctx context.Context, downstream net.Conn, host string, destination netip.AddrPort) error {
	upstream := newHTTP2UpstreamRoundTripper(host, destination, p.openUpstreamHTTP2TLS)
	defer upstream.Close()

	var (
		handlerErr error
		errOnce    sync.Once
	)
	fail := func(err error) {
		if err == nil {
			return
		}
		errOnce.Do(func() {
			handlerErr = err
			_ = downstream.Close()
		})
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if mismatch, authority := requestAuthorityMismatch(host, req); mismatch {
			if p.mode == config.ModeAudit {
				p.logAuthorityMismatch(destination.Port(), host, authority, req.Method, requestPath(req))
			} else {
				http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
				return
			}
		}

		action, matchedMITM := p.requestAction(host, destination.Port(), req)
		if !p.allowAction(action) {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		if shouldLogAction(action, p.mode) {
			p.logWouldDeny(destination.Port(), host, req.Method, requestPath(req), action, matchedMITM)
		}

		upstreamReq := req.Clone(req.Context())
		upstreamReq.RequestURI = ""
		upstreamReq.URL = cloneUpstreamURL(req.URL, host)
		upstreamReq.Host = req.Host

		resp, err := upstream.RoundTrip(upstreamReq)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		copyHeader(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		if _, err := io.Copy(w, resp.Body); err != nil {
			fail(fmt.Errorf("forward downstream http response for %q: %w", host, err))
		}
	})

	server := &http2.Server{
		IdleTimeout: p.idleTimeout,
	}
	server.ServeConn(downstream, &http2.ServeConnOpts{
		Context: ctx,
		Handler: handler,
		BaseConfig: &http.Server{
			Handler:           handler,
			IdleTimeout:       p.idleTimeout,
			ReadHeaderTimeout: p.idleTimeout,
			MaxHeaderBytes:    p.maxHeaderBytes,
		},
	})

	return handlerErr
}

type upstreamTLSRoundTripper struct {
	host        string
	destination netip.AddrPort
	open        func(context.Context, string, netip.AddrPort) (net.Conn, error)

	mu          sync.Mutex
	initialized bool
	h2Transport *http2.Transport
	h2Conn      *http2.ClientConn
	h1Transport *http.Transport
}

func newHTTP2UpstreamRoundTripper(
	host string,
	destination netip.AddrPort,
	open func(context.Context, string, netip.AddrPort) (net.Conn, error),
) *upstreamTLSRoundTripper {
	return &upstreamTLSRoundTripper{
		host:        host,
		destination: destination,
		open:        open,
	}
}

func (r *upstreamTLSRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	h2Conn, h1Transport, err := r.ensureInitialized(req.Context())
	if err != nil {
		return nil, err
	}
	if h2Conn != nil {
		return h2Conn.RoundTrip(req)
	}
	return h1Transport.RoundTrip(req)
}

func (r *upstreamTLSRoundTripper) ensureInitialized(ctx context.Context) (*http2.ClientConn, *http.Transport, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.initialized {
		return r.h2Conn, r.h1Transport, nil
	}

	conn, err := r.open(ctx, r.host, r.destination)
	if err != nil {
		return nil, nil, err
	}

	if negotiatedProtocol(conn) == "h2" {
		transport := &http2.Transport{}
		clientConn, err := transport.NewClientConn(conn)
		if err != nil {
			_ = conn.Close()
			return nil, nil, err
		}
		r.h2Transport = transport
		r.h2Conn = clientConn
	} else {
		_ = conn.Close()
		r.h1Transport = &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return r.open(ctx, r.host, r.destination)
			},
		}
	}

	r.initialized = true
	return r.h2Conn, r.h1Transport, nil
}

func (r *upstreamTLSRoundTripper) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	var firstErr error
	if r.h2Conn != nil {
		if err := r.h2Conn.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if r.h1Transport != nil {
		r.h1Transport.CloseIdleConnections()
	}
	return firstErr
}

func negotiatedProtocol(conn net.Conn) string {
	type tlsStateConn interface {
		ConnectionState() tls.ConnectionState
	}
	stateful, ok := conn.(tlsStateConn)
	if !ok {
		return ""
	}
	return stateful.ConnectionState().NegotiatedProtocol
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

	downstream = withIdleTimeout(downstream, p.idleTimeout)
	upstream = withIdleTimeout(upstream, p.idleTimeout)
	stopCancel := closeOnContextDone(ctx, downstream, upstream)
	defer stopCancel()

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

func requestAuthorityMismatch(classifiedHost string, req *http.Request) (bool, string) {
	authority := requestAuthority(req)
	return normalizeAuthorityHost(authority) != classifiedHost, authority
}

func requestAuthority(req *http.Request) string {
	if req == nil {
		return ""
	}
	if authority := strings.TrimSpace(req.Host); authority != "" {
		return authority
	}
	if req.URL != nil {
		return strings.TrimSpace(req.URL.Host)
	}
	return ""
}

func normalizeAuthorityHost(authority string) string {
	authority = strings.TrimSpace(authority)
	if authority == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(authority); err == nil {
		authority = host
	}
	return policy.NormalizeHostname(authority)
}

func cloneUpstreamURL(src *url.URL, host string) *url.URL {
	dst := &url.URL{
		Scheme: "https",
		Host:   host,
		Path:   "/",
	}
	if src == nil {
		return dst
	}
	*dst = *src
	dst.Scheme = "https"
	dst.Host = host
	if dst.Path == "" {
		dst.Path = "/"
	}
	return dst
}

func copyHeader(dst, src http.Header) {
	for key, values := range src {
		dst[key] = append([]string(nil), values...)
	}
}

func requestWantsClose(req *http.Request) bool {
	if req == nil {
		return false
	}
	return req.Close || strings.EqualFold(req.Header.Get("Connection"), "close")
}

func responseWantsClose(resp *http.Response) bool {
	if resp == nil {
		return false
	}
	return resp.Close || strings.EqualFold(resp.Header.Get("Connection"), "close")
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

func (p *Proxy) logAuthorityMismatch(port uint16, host, authority, method, path string) {
	p.logger.Info("would_deny_https",
		"reason", "authority_mismatch",
		"host", host,
		"authority", authority,
		"port", port,
		"method", method,
		"path", path,
		"action", string(httppolicy.ActionDeny),
	)
}

func (p *Proxy) readerBufferSize() int {
	return p.maxHeaderBytes + 1
}

func ensureHeaderLimit(reader *bufio.Reader, limit int) error {
	if limit <= 0 {
		return nil
	}

	for {
		if buffered := reader.Buffered(); buffered > 0 {
			buf, err := reader.Peek(buffered)
			if err == nil {
				if headerTerminatorIndex(buf) >= 0 {
					return nil
				}
				if len(buf) > limit {
					return ErrHTTPSRequestHeadersTooLarge
				}
			}
		}

		need := reader.Buffered() + 1
		if need < 1 {
			need = 1
		}
		if need > limit+1 {
			need = limit + 1
		}

		buf, err := reader.Peek(need)
		if headerTerminatorIndex(buf) >= 0 {
			return nil
		}
		if len(buf) > limit || errors.Is(err, bufio.ErrBufferFull) {
			return ErrHTTPSRequestHeadersTooLarge
		}
		if err != nil {
			return err
		}
	}
}

func headerTerminatorIndex(buf []byte) int {
	if i := bytes.Index(buf, []byte("\r\n\r\n")); i >= 0 {
		return i
	}
	return bytes.Index(buf, []byte("\n\n"))
}

func isBenignReadTermination(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed)
}

type idleTimeoutConn struct {
	net.Conn
	timeout   time.Duration
	activity  chan struct{}
	done      chan struct{}
	timedOut  atomic.Bool
	closeOnce sync.Once
}

func withIdleTimeout(conn net.Conn, timeout time.Duration) net.Conn {
	if conn == nil || timeout <= 0 {
		return conn
	}
	c := &idleTimeoutConn{
		Conn:     conn,
		timeout:  timeout,
		activity: make(chan struct{}, 1),
		done:     make(chan struct{}),
	}
	go c.watchIdle()
	c.touch()
	return c
}

func (c *idleTimeoutConn) Read(p []byte) (int, error) {
	c.touch()
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.touch()
	}
	if err != nil && c.timedOut.Load() {
		return n, os.ErrDeadlineExceeded
	}
	return n, err
}

func (c *idleTimeoutConn) Write(p []byte) (int, error) {
	c.touch()
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.touch()
	}
	if err != nil && c.timedOut.Load() {
		return n, os.ErrDeadlineExceeded
	}
	return n, err
}

func (c *idleTimeoutConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.done)
	})
	return c.Conn.Close()
}

func (c *idleTimeoutConn) touch() {
	select {
	case c.activity <- struct{}{}:
	default:
	}
}

func (c *idleTimeoutConn) watchIdle() {
	timer := time.NewTimer(c.timeout)
	defer timer.Stop()

	for {
		select {
		case <-timer.C:
			c.timedOut.Store(true)
			_ = c.Conn.Close()
			return
		case <-c.activity:
			c.timedOut.Store(false)
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(c.timeout)
		case <-c.done:
			return
		}
	}
}

func closeOnContextDone(ctx context.Context, conns ...net.Conn) func() {
	if ctx == nil || ctx.Done() == nil {
		return func() {}
	}

	stopped := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			for _, conn := range conns {
				if conn != nil {
					_ = conn.Close()
				}
			}
		case <-stopped:
		}
	}()
	return func() {
		close(stopped)
	}
}
