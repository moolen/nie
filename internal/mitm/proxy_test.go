package mitm

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/moolen/nie/internal/config"
	"github.com/moolen/nie/internal/httppolicy"
	"github.com/moolen/nie/internal/policy"
	"golang.org/x/net/http2"
)

func TestProxy_AllowsRequestWhenMITMRuleMatches(t *testing.T) {
	logger, logs := testLogger()
	proxy := newTestProxy(t, testProxyOptions{
		logger: logger,
		mitmRules: []httppolicy.Rule{
			{
				Host:    "api.github.com",
				Port:    443,
				Methods: []string{"GET"},
				Paths:   []string{"/allowed"},
				Action:  httppolicy.ActionAllow,
			},
		},
		upstreamResponseBody: "allowed",
	})

	statusCode, body, req, err := roundTripHTTPSRequest(t, proxy, roundTripConfig{
		serverName: "api.github.com",
		hostHeader: "api.github.com",
		method:     http.MethodGet,
		path:       "/allowed",
	})
	if err != nil {
		t.Fatalf("roundTripHTTPSRequest() error = %v", err)
	}
	if statusCode != http.StatusOK {
		t.Fatalf("response status = %d, want 200", statusCode)
	}
	if body != "allowed" {
		t.Fatalf("response body = %q, want %q", body, "allowed")
	}
	if req.Host != "api.github.com" {
		t.Fatalf("upstream request host = %q, want api.github.com", req.Host)
	}
	if strings.Contains(logs.String(), "would_deny_https") {
		t.Fatalf("log output = %q, want no would_deny_https entry", logs.String())
	}
}

func TestProxy_DeniesMissingSNIInEnforceMode(t *testing.T) {
	logger, _ := testLogger()
	for _, action := range []httppolicy.Action{httppolicy.ActionDeny, httppolicy.ActionAudit} {
		t.Run(string(action), func(t *testing.T) {
			proxy := newTestProxy(t, testProxyOptions{
				logger:           logger,
				mode:             config.ModeEnforce,
				missingSNIAction: action,
			})

			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()

			done := make(chan error, 1)
			go func() {
				done <- proxy.HandleClassifiedConnection(context.Background(), ClassifiedConn{
					Conn:                serverConn,
					OriginalDestination: netip.MustParseAddrPort("203.0.113.10:443"),
					MissingSNI:          true,
				})
			}()

			if err := clientConn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatalf("clientConn.SetReadDeadline() error = %v", err)
			}
			_, err := clientConn.Read(make([]byte, 1))
			if err == nil {
				t.Fatal("client read error = nil, want closed connection")
			}

			if err := <-done; err == nil {
				t.Fatal("HandleClassifiedConnection() error = nil, want deny")
			}
		})
	}
}

func TestProxy_MissingSNIInAuditMode(t *testing.T) {
	t.Run("deny still denies", func(t *testing.T) {
		logger, logs := testLogger()
		proxy := newTestProxy(t, testProxyOptions{
			logger:           logger,
			mode:             config.ModeAudit,
			missingSNIAction: httppolicy.ActionDeny,
		})

		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()

		done := make(chan error, 1)
		go func() {
			done <- proxy.HandleClassifiedConnection(context.Background(), ClassifiedConn{
				Conn:                serverConn,
				OriginalDestination: netip.MustParseAddrPort("203.0.113.10:443"),
				MissingSNI:          true,
			})
		}()

		if err := clientConn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatalf("clientConn.SetReadDeadline() error = %v", err)
		}
		_, err := clientConn.Read(make([]byte, 1))
		if err == nil {
			t.Fatal("client read error = nil, want closed connection")
		}
		if err := <-done; err == nil {
			t.Fatal("HandleClassifiedConnection() error = nil, want deny")
		}
		if strings.Contains(logs.String(), "would_deny_https") {
			t.Fatalf("log output = %q, want no missing_sni audit log", logs.String())
		}
	})

	t.Run("audit logs and tunnels", func(t *testing.T) {
		logger, logs := testLogger()
		proxy := newTestProxy(t, testProxyOptions{
			logger:               logger,
			mode:                 config.ModeAudit,
			missingSNIAction:     httppolicy.ActionAudit,
			enableRawTCPUpstream: true,
			rawUpstreamReply:     "opaque-ok",
		})

		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()

		done := make(chan error, 1)
		go func() {
			done <- proxy.HandleClassifiedConnection(context.Background(), ClassifiedConn{
				Conn:                serverConn,
				OriginalDestination: netip.MustParseAddrPort("203.0.113.10:443"),
				MissingSNI:          true,
			})
		}()

		if _, err := io.WriteString(clientConn, "opaque-client"); err != nil {
			t.Fatalf("client write error = %v", err)
		}
		if err := clientConn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatalf("clientConn.SetReadDeadline() error = %v", err)
		}
		buf := make([]byte, len("opaque-ok"))
		if _, err := io.ReadFull(clientConn, buf); err != nil {
			t.Fatalf("client read error = %v", err)
		}
		_ = clientConn.Close()

		if err := <-done; err != nil {
			t.Fatalf("HandleClassifiedConnection() error = %v", err)
		}
		if got := string(buf); got != "opaque-ok" {
			t.Fatalf("opaque response = %q, want %q", got, "opaque-ok")
		}
		if !strings.Contains(logs.String(), "would_deny_https") || !strings.Contains(logs.String(), "missing_sni") {
			t.Fatalf("log output = %q, want missing_sni audit log", logs.String())
		}
	})
}

func TestProxy_AuditsAndForwardsDeniedRequestInAuditMode(t *testing.T) {
	logger, logs := testLogger()
	proxy := newTestProxy(t, testProxyOptions{
		logger: logger,
		mode:   config.ModeAudit,
		mitmRules: []httppolicy.Rule{
			{
				Host:    "api.github.com",
				Port:    443,
				Methods: []string{"GET"},
				Paths:   []string{"/denied"},
				Action:  httppolicy.ActionDeny,
			},
		},
		upstreamResponseBody: "audited",
	})

	statusCode, body, _, err := roundTripHTTPSRequest(t, proxy, roundTripConfig{
		serverName: "api.github.com",
		hostHeader: "api.github.com",
		method:     http.MethodGet,
		path:       "/denied",
	})
	if err != nil {
		t.Fatalf("roundTripHTTPSRequest() error = %v", err)
	}
	if statusCode != http.StatusOK {
		t.Fatalf("response status = %d, want 200", statusCode)
	}
	if body != "audited" {
		t.Fatalf("response body = %q, want %q", body, "audited")
	}
	if !strings.Contains(logs.String(), "would_deny_https") {
		t.Fatalf("log output = %q, want would_deny_https entry", logs.String())
	}
}

func TestProxy_FallsBackToHostnamePolicyWhenNoMITMRuleMatches(t *testing.T) {
	logger, _ := testLogger()
	proxy := newTestProxy(t, testProxyOptions{
		logger:        logger,
		fallbackAllow: []string{"api.github.com"},
		mitmRules: []httppolicy.Rule{
			{
				Host:    "api.github.com",
				Port:    443,
				Methods: []string{"POST"},
				Paths:   []string{"/allowed"},
				Action:  httppolicy.ActionAllow,
			},
		},
		upstreamResponseBody: "fallback",
	})

	statusCode, body, _, err := roundTripHTTPSRequest(t, proxy, roundTripConfig{
		serverName: "api.github.com",
		hostHeader: "api.github.com",
		method:     http.MethodGet,
		path:       "/allowed",
	})
	if err != nil {
		t.Fatalf("roundTripHTTPSRequest() error = %v", err)
	}
	if statusCode != http.StatusOK {
		t.Fatalf("response status = %d, want 200", statusCode)
	}
	if body != "fallback" {
		t.Fatalf("response body = %q, want %q", body, "fallback")
	}
}

func TestProxy_UsesSNIInsteadOfHTTPHostHeaderForPolicy(t *testing.T) {
	logger, _ := testLogger()
	proxy := newTestProxy(t, testProxyOptions{
		logger: logger,
		mitmRules: []httppolicy.Rule{
			{
				Host:    "allowed.example.com",
				Port:    443,
				Methods: []string{"GET"},
				Paths:   []string{"/"},
				Action:  httppolicy.ActionAllow,
			},
		},
		upstreamResponseBody: "sni-wins",
	})

	statusCode, _, req, err := roundTripHTTPSRequest(t, proxy, roundTripConfig{
		serverName: "allowed.example.com",
		hostHeader: "evil.example.com",
		method:     http.MethodGet,
		path:       "/",
	})
	if err != nil {
		t.Fatalf("roundTripHTTPSRequest() error = %v", err)
	}
	if statusCode != http.StatusOK {
		t.Fatalf("response status = %d, want 200", statusCode)
	}
	if req.Host != "evil.example.com" {
		t.Fatalf("upstream request host = %q, want original untrusted Host header preserved", req.Host)
	}
}

func TestProxy_HandlesMultipleRequestsOnOneConnection(t *testing.T) {
	logger, _ := testLogger()
	proxy := newTestProxy(t, testProxyOptions{
		logger: logger,
		mitmRules: []httppolicy.Rule{
			{
				Host:    "api.github.com",
				Port:    443,
				Methods: []string{"GET"},
				Paths:   []string{"/first", "/second"},
				Action:  httppolicy.ActionAllow,
			},
		},
		upstreamResponseBody: "keepalive",
	})

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	done := make(chan error, 1)
	go func() {
		done <- proxy.HandleClassifiedConnection(context.Background(), ClassifiedConn{
			Conn:                serverConn,
			OriginalDestination: netip.MustParseAddrPort("203.0.113.10:443"),
			ClientHello:         ClientHello{ServerName: "api.github.com"},
		})
	}()

	clientTLS := tls.Client(clientConn, &tls.Config{
		ServerName: "api.github.com",
		RootCAs:    proxy.testRootCAs(),
		MinVersion: tls.VersionTLS12,
	})
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("clientTLS.Handshake() error = %v", err)
	}

	reader := bufio.NewReader(clientTLS)
	for _, path := range []string{"/first", "/second"} {
		reqText := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: api.github.com\r\n\r\n", path)
		if _, err := io.WriteString(clientTLS, reqText); err != nil {
			t.Fatalf("write request for %s: %v", path, err)
		}
		resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
		if err != nil {
			t.Fatalf("read response for %s: %v", path, err)
		}
		if body := readResponseBody(t, resp); body != "keepalive" {
			t.Fatalf("response body for %s = %q, want %q", path, body, "keepalive")
		}
	}

	_ = clientConn.Close()
	if err := <-done; err != nil {
		t.Fatalf("HandleClassifiedConnection() error = %v", err)
	}
	if proxy.upstreamDialCount() != 1 {
		t.Fatalf("upstream dial count = %d, want 1", proxy.upstreamDialCount())
	}
}

func TestProxy_TimesOutStalledDownstreamConnection(t *testing.T) {
	logger, _ := testLogger()
	proxy := newTestProxy(t, testProxyOptions{
		logger:      logger,
		idleTimeout: 25 * time.Millisecond,
		mitmRules: []httppolicy.Rule{
			{
				Host:    "api.github.com",
				Port:    443,
				Methods: []string{"GET"},
				Paths:   []string{"/"},
				Action:  httppolicy.ActionAllow,
			},
		},
	})

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	done := make(chan error, 1)
	go func() {
		done <- proxy.HandleClassifiedConnection(context.Background(), ClassifiedConn{
			Conn:                serverConn,
			OriginalDestination: netip.MustParseAddrPort("203.0.113.10:443"),
			ClientHello:         ClientHello{ServerName: "api.github.com"},
		})
	}()

	clientTLS := tls.Client(clientConn, &tls.Config{
		ServerName: "api.github.com",
		RootCAs:    proxy.testRootCAs(),
		MinVersion: tls.VersionTLS12,
	})
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("clientTLS.Handshake() error = %v", err)
	}

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("HandleClassifiedConnection() error = nil, want timeout")
		}
		if !strings.Contains(err.Error(), "timeout") && !strings.Contains(err.Error(), "deadline") {
			t.Fatalf("HandleClassifiedConnection() error = %v, want timeout context", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for proxy timeout")
	}
}

func TestProxy_DeniesRequestHeadersAboveLimit(t *testing.T) {
	logger, _ := testLogger()
	proxy := newTestProxy(t, testProxyOptions{
		logger:         logger,
		maxHeaderBytes: 128,
		mitmRules: []httppolicy.Rule{
			{
				Host:    "api.github.com",
				Port:    443,
				Methods: []string{"GET"},
				Paths:   []string{"/"},
				Action:  httppolicy.ActionAllow,
			},
		},
	})

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	done := make(chan error, 1)
	go func() {
		done <- proxy.HandleClassifiedConnection(context.Background(), ClassifiedConn{
			Conn:                serverConn,
			OriginalDestination: netip.MustParseAddrPort("203.0.113.10:443"),
			ClientHello:         ClientHello{ServerName: "api.github.com"},
		})
	}()

	clientTLS := tls.Client(clientConn, &tls.Config{
		ServerName: "api.github.com",
		RootCAs:    proxy.testRootCAs(),
		MinVersion: tls.VersionTLS12,
	})
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("clientTLS.Handshake() error = %v", err)
	}

	oversizedValue := strings.Repeat("a", 256)
	reqText := "GET / HTTP/1.1\r\nHost: api.github.com\r\nX-Large: " + oversizedValue + "\r\n\r\n"
	if _, err := io.WriteString(clientTLS, reqText); err != nil {
		t.Fatalf("write oversized request: %v", err)
	}
	_ = clientConn.Close()

	err := <-done
	if !errors.Is(err, ErrHTTPSRequestHeadersTooLarge) {
		t.Fatalf("HandleClassifiedConnection() error = %v, want %v", err, ErrHTTPSRequestHeadersTooLarge)
	}
	if proxy.upstreamDialCount() != 0 {
		t.Fatalf("upstream dial count = %d, want 0", proxy.upstreamDialCount())
	}
}

func TestProxy_HandlesConcurrentHTTPSConnections(t *testing.T) {
	logger, _ := testLogger()
	proxy := newTestProxy(t, testProxyOptions{
		logger: logger,
		mitmRules: []httppolicy.Rule{
			{
				Host:    "api.github.com",
				Port:    443,
				Methods: []string{"GET"},
				Paths:   []string{"/**"},
				Action:  httppolicy.ActionAllow,
			},
		},
		upstreamResponseBody: "parallel",
	})

	const flows = 8
	errCh := make(chan error, flows)
	var wg sync.WaitGroup
	for i := 0; i < flows; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			path := fmt.Sprintf("/req-%d", i)
			statusCode, body, _, err := roundTripHTTPSRequest(t, proxy, roundTripConfig{
				serverName: "api.github.com",
				hostHeader: "api.github.com",
				method:     http.MethodGet,
				path:       path,
			})
			if err != nil {
				errCh <- fmt.Errorf("flow %d: %w", i, err)
				return
			}
			if statusCode != http.StatusOK {
				errCh <- fmt.Errorf("flow %d: status=%d", i, statusCode)
				return
			}
			if body != "parallel" {
				errCh <- fmt.Errorf("flow %d: body=%q", i, body)
				return
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	if proxy.upstreamDialCount() != flows {
		t.Fatalf("upstream dial count = %d, want %d", proxy.upstreamDialCount(), flows)
	}
}

func TestProxy_HandlesConcurrentHTTP2StreamsOnOneConnection(t *testing.T) {
	logger, _ := testLogger()
	releaseResponses := make(chan struct{})
	proxy := newTestProxy(t, testProxyOptions{
		logger: logger,
		mitmRules: []httppolicy.Rule{
			{
				Host:    "api.github.com",
				Port:    443,
				Methods: []string{"GET"},
				Paths:   []string{"/first", "/second"},
				Action:  httppolicy.ActionAllow,
			},
		},
		upstreamResponseBody: "h2",
		upstreamResponseGate: releaseResponses,
		upstreamHTTP2:        true,
	})

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	done := make(chan error, 1)
	go func() {
		done <- proxy.HandleClassifiedConnection(context.Background(), ClassifiedConn{
			Conn:                serverConn,
			OriginalDestination: netip.MustParseAddrPort("203.0.113.10:443"),
			ClientHello:         ClientHello{ServerName: "api.github.com"},
		})
	}()

	clientTLS := tls.Client(clientConn, &tls.Config{
		ServerName: "api.github.com",
		RootCAs:    proxy.testRootCAs(),
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2"},
	})
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("clientTLS.Handshake() error = %v", err)
	}
	if got := clientTLS.ConnectionState().NegotiatedProtocol; got != "h2" {
		t.Fatalf("negotiated protocol = %q, want %q", got, "h2")
	}

	h2Transport := &http2.Transport{}
	h2Conn, err := h2Transport.NewClientConn(clientTLS)
	if err != nil {
		t.Fatalf("http2.Transport.NewClientConn() error = %v", err)
	}
	defer h2Transport.CloseIdleConnections()

	type result struct {
		path string
		body string
		err  error
	}
	resultCh := make(chan result, 2)
	start := make(chan struct{})
	for _, path := range []string{"/first", "/second"} {
		go func(path string) {
			<-start
			req, err := http.NewRequest(http.MethodGet, "https://api.github.com"+path, nil)
			if err != nil {
				resultCh <- result{path: path, err: err}
				return
			}
			resp, err := h2Conn.RoundTrip(req)
			if err != nil {
				resultCh <- result{path: path, err: err}
				return
			}
			resultCh <- result{path: path, body: readResponseBody(t, resp)}
		}(path)
	}
	close(start)

	seen := map[string]bool{}
	for len(seen) < 2 {
		select {
		case req := <-proxy.upstream.requests:
			seen[requestPath(req)] = true
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for concurrent upstream requests, saw=%v", seen)
		}
	}

	close(releaseResponses)

	for i := 0; i < 2; i++ {
		res := <-resultCh
		if res.err != nil {
			t.Fatalf("RoundTrip(%s) error = %v", res.path, res.err)
		}
		if res.body != "h2" {
			t.Fatalf("response body for %s = %q, want %q", res.path, res.body, "h2")
		}
	}

	_ = clientConn.Close()
	if err := <-done; err != nil {
		t.Fatalf("HandleClassifiedConnection() error = %v", err)
	}
	if proxy.upstreamDialCount() != 1 {
		t.Fatalf("upstream dial count = %d, want 1", proxy.upstreamDialCount())
	}
}

func TestProxy_KeepsHTTP2ConnectionAliveAfterDeniedStream(t *testing.T) {
	logger, _ := testLogger()
	proxy := newTestProxy(t, testProxyOptions{
		logger: logger,
		mitmRules: []httppolicy.Rule{
			{
				Host:    "api.github.com",
				Port:    443,
				Methods: []string{"GET"},
				Paths:   []string{"/allowed"},
				Action:  httppolicy.ActionAllow,
			},
		},
		upstreamResponseBody: "ok",
	})

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	done := make(chan error, 1)
	go func() {
		done <- proxy.HandleClassifiedConnection(context.Background(), ClassifiedConn{
			Conn:                serverConn,
			OriginalDestination: netip.MustParseAddrPort("203.0.113.10:443"),
			ClientHello:         ClientHello{ServerName: "api.github.com"},
		})
	}()

	clientTLS := tls.Client(clientConn, &tls.Config{
		ServerName: "api.github.com",
		RootCAs:    proxy.testRootCAs(),
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2"},
	})
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("clientTLS.Handshake() error = %v", err)
	}
	if got := clientTLS.ConnectionState().NegotiatedProtocol; got != "h2" {
		t.Fatalf("negotiated protocol = %q, want %q", got, "h2")
	}

	h2Transport := &http2.Transport{}
	h2Conn, err := h2Transport.NewClientConn(clientTLS)
	if err != nil {
		t.Fatalf("http2.Transport.NewClientConn() error = %v", err)
	}
	defer h2Transport.CloseIdleConnections()

	deniedReq, err := http.NewRequest(http.MethodGet, "https://api.github.com/denied", nil)
	if err != nil {
		t.Fatalf("http.NewRequest(denied) error = %v", err)
	}
	deniedResp, err := h2Conn.RoundTrip(deniedReq)
	if err != nil {
		t.Fatalf("RoundTrip(denied) error = %v", err)
	}
	if deniedResp.StatusCode != http.StatusForbidden {
		t.Fatalf("denied response status = %d, want %d", deniedResp.StatusCode, http.StatusForbidden)
	}
	_ = deniedResp.Body.Close()

	select {
	case req := <-proxy.upstream.requests:
		t.Fatalf("unexpected upstream request for denied stream: %s %s", req.Method, requestPath(req))
	case <-time.After(100 * time.Millisecond):
	}

	allowedReq, err := http.NewRequest(http.MethodGet, "https://api.github.com/allowed", nil)
	if err != nil {
		t.Fatalf("http.NewRequest(allowed) error = %v", err)
	}
	allowedResp, err := h2Conn.RoundTrip(allowedReq)
	if err != nil {
		t.Fatalf("RoundTrip(allowed) error = %v", err)
	}
	if allowedResp.StatusCode != http.StatusOK {
		t.Fatalf("allowed response status = %d, want %d", allowedResp.StatusCode, http.StatusOK)
	}
	if body := readResponseBody(t, allowedResp); body != "ok" {
		t.Fatalf("allowed response body = %q, want %q", body, "ok")
	}

	select {
	case req := <-proxy.upstream.requests:
		if requestPath(req) != "/allowed" {
			t.Fatalf("upstream request path = %q, want %q", requestPath(req), "/allowed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for upstream request for allowed stream")
	}

	_ = clientConn.Close()
	if err := <-done; err != nil {
		t.Fatalf("HandleClassifiedConnection() error = %v", err)
	}
}

func TestProxy_DeniesInvalidHTTPAfterTLSHandshake(t *testing.T) {
	logger, _ := testLogger()
	proxy := newTestProxy(t, testProxyOptions{
		logger: logger,
		mitmRules: []httppolicy.Rule{
			{
				Host:    "api.github.com",
				Port:    443,
				Methods: []string{"GET"},
				Paths:   []string{"/allowed"},
				Action:  httppolicy.ActionAllow,
			},
		},
	})

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	done := make(chan error, 1)
	go func() {
		done <- proxy.HandleClassifiedConnection(context.Background(), ClassifiedConn{
			Conn:                serverConn,
			OriginalDestination: netip.MustParseAddrPort("203.0.113.10:443"),
			ClientHello:         ClientHello{ServerName: "api.github.com"},
		})
	}()

	clientTLS := tls.Client(clientConn, &tls.Config{
		ServerName: "api.github.com",
		RootCAs:    proxy.testRootCAs(),
		MinVersion: tls.VersionTLS12,
	})
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("clientTLS.Handshake() error = %v", err)
	}
	if _, err := io.WriteString(clientTLS, "not http\r\n\r\n"); err != nil {
		t.Fatalf("write invalid HTTP payload: %v", err)
	}
	_ = clientConn.Close()

	if err := <-done; err == nil {
		t.Fatal("HandleClassifiedConnection() error = nil, want invalid HTTP denial")
	}
	if proxy.upstreamRequestCount() != 0 {
		t.Fatalf("upstream request count = %d, want 0", proxy.upstreamRequestCount())
	}
}

func TestProxy_DeniesUpstreamTrustFailure(t *testing.T) {
	logger, _ := testLogger()
	proxy := newTestProxy(t, testProxyOptions{
		logger: logger,
		mitmRules: []httppolicy.Rule{
			{
				Host:    "api.github.com",
				Port:    443,
				Methods: []string{"GET"},
				Paths:   []string{"/allowed"},
				Action:  httppolicy.ActionAllow,
			},
		},
		upstreamErr: errors.New("x509: certificate signed by unknown authority"),
	})

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	done := make(chan error, 1)
	go func() {
		done <- proxy.HandleClassifiedConnection(context.Background(), ClassifiedConn{
			Conn:                serverConn,
			OriginalDestination: netip.MustParseAddrPort("203.0.113.10:443"),
			ClientHello:         ClientHello{ServerName: "api.github.com"},
		})
	}()

	clientTLS := tls.Client(clientConn, &tls.Config{
		ServerName: "api.github.com",
		RootCAs:    proxy.testRootCAs(),
		MinVersion: tls.VersionTLS12,
	})
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("clientTLS.Handshake() error = %v", err)
	}
	if _, err := io.WriteString(clientTLS, "GET /allowed HTTP/1.1\r\nHost: api.github.com\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("write request: %v", err)
	}
	_ = clientConn.Close()

	if err := <-done; err == nil {
		t.Fatal("HandleClassifiedConnection() error = nil, want upstream trust failure")
	}
}

type testProxyOptions struct {
	logger               *slog.Logger
	mode                 config.Mode
	missingSNIAction     httppolicy.Action
	defaultAction        httppolicy.Action
	idleTimeout          time.Duration
	maxHeaderBytes       int
	fallbackAllow        []string
	mitmRules            []httppolicy.Rule
	upstreamResponseBody string
	upstreamResponseGate <-chan struct{}
	upstreamHTTP2        bool
	upstreamErr          error
	rawUpstreamReply     string
	enableRawTCPUpstream bool
}

type roundTripConfig struct {
	serverName string
	hostHeader string
	method     string
	path       string
}

type testProxy struct {
	*Proxy

	authority *Authority
	upstream  *recordingUpstream
}

func newTestProxy(t *testing.T, opts testProxyOptions) *testProxy {
	t.Helper()

	if opts.logger == nil {
		opts.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if opts.mode == "" {
		opts.mode = config.ModeEnforce
	}
	if opts.missingSNIAction == "" {
		opts.missingSNIAction = httppolicy.ActionDeny
	}
	if opts.defaultAction == "" {
		opts.defaultAction = httppolicy.ActionDeny
	}

	authority := newProxyTestAuthority(t)
	leafCache := NewLeafCache(authority, func() time.Time { return time.Now().UTC() })

	httpPolicy, err := httppolicy.New(opts.mitmRules)
	if err != nil {
		t.Fatalf("httppolicy.New() error = %v", err)
	}
	fallbackPolicy, err := policy.New(opts.fallbackAllow)
	if err != nil {
		t.Fatalf("policy.New() error = %v", err)
	}

	upstream := &recordingUpstream{
		responseBody:     opts.upstreamResponseBody,
		responseGate:     opts.upstreamResponseGate,
		http2:            opts.upstreamHTTP2,
		leafCertificates: leafCache,
		err:              opts.upstreamErr,
		requests:         make(chan *http.Request, 8),
		rawReply:         opts.rawUpstreamReply,
	}

	proxy, err := NewProxy(ProxyConfig{
		Mode:             opts.mode,
		MissingSNIAction: opts.missingSNIAction,
		DefaultAction:    opts.defaultAction,
		IdleTimeout:      opts.idleTimeout,
		MaxHeaderBytes:   opts.maxHeaderBytes,
	}, ProxyDependencies{
		Logger:           opts.logger,
		MITMPolicy:       httpPolicy,
		HostnamePolicy:   fallbackPolicy,
		LeafCertificates: leafCache,
		OpenUpstreamTLS:  upstream.dialTLS,
		OpenUpstreamTCP: func(ctx context.Context, destination netip.AddrPort) (net.Conn, error) {
			if !opts.enableRawTCPUpstream {
				return nil, errors.New("raw upstream disabled in test")
			}
			return upstream.dialRaw(ctx, destination)
		},
	})
	if err != nil {
		t.Fatalf("NewProxy() error = %v", err)
	}

	return &testProxy{
		Proxy:     proxy,
		authority: authority,
		upstream:  upstream,
	}
}

func (p *testProxy) testRootCAs() *x509.CertPool {
	roots := x509.NewCertPool()
	roots.AddCert(p.authority.Cert)
	return roots
}

func (p *testProxy) upstreamRequestCount() int {
	return len(p.upstream.requests)
}

func (p *testProxy) upstreamDialCount() int {
	return p.upstream.dialCount()
}

func roundTripHTTPSRequest(t *testing.T, proxy *testProxy, cfg roundTripConfig) (int, string, *http.Request, error) {
	t.Helper()

	clientConn, serverConn := net.Pipe()

	done := make(chan error, 1)
	go func() {
		done <- proxy.HandleClassifiedConnection(context.Background(), ClassifiedConn{
			Conn:                serverConn,
			OriginalDestination: netip.MustParseAddrPort("203.0.113.10:443"),
			ClientHello:         ClientHello{ServerName: cfg.serverName},
		})
	}()

	clientTLS := tls.Client(clientConn, &tls.Config{
		ServerName: cfg.serverName,
		RootCAs:    proxy.testRootCAs(),
		MinVersion: tls.VersionTLS12,
	})
	if err := clientTLS.Handshake(); err != nil {
		return 0, "", nil, fmt.Errorf("downstream tls handshake: %w", err)
	}

	reqText := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", cfg.method, cfg.path, cfg.hostHeader)
	if _, err := io.WriteString(clientTLS, reqText); err != nil {
		return 0, "", nil, fmt.Errorf("write downstream request: %w", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(clientTLS), &http.Request{Method: cfg.method})
	if err != nil {
		return 0, "", nil, fmt.Errorf("read downstream response: %w", err)
	}
	body := readResponseBody(t, resp)

	var upstreamReq *http.Request
	select {
	case upstreamReq = <-proxy.upstream.requests:
	case <-time.After(2 * time.Second):
		return 0, "", nil, errors.New("timed out waiting for upstream request")
	}

	_ = clientConn.Close()
	if err := <-done; err != nil {
		return 0, "", nil, fmt.Errorf("proxy handler: %w", err)
	}
	return resp.StatusCode, body, upstreamReq, nil
}

func readResponseBody(t *testing.T, resp *http.Response) string {
	t.Helper()

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll(response body) error = %v", err)
	}
	return string(body)
}

type recordingUpstream struct {
	responseBody     string
	responseGate     <-chan struct{}
	http2            bool
	leafCertificates interface {
		CertificateForHost(string) (*tls.Certificate, error)
	}
	err      error
	requests chan *http.Request
	rawReply string

	mu        sync.Mutex
	dialCalls int
}

func (u *recordingUpstream) dialTLS(_ context.Context, serverName string, _ netip.AddrPort) (net.Conn, error) {
	if u.err != nil {
		return nil, u.err
	}
	u.mu.Lock()
	u.dialCalls++
	u.mu.Unlock()
	if u.http2 {
		return u.dialHTTP2TLS(serverName)
	}

	return u.dialHTTP1TLS(), nil
}

func (u *recordingUpstream) dialHTTP1TLS() net.Conn {
	clientConn, serverConn := net.Pipe()
	go func() {
		defer serverConn.Close()
		reader := bufio.NewReader(serverConn)

		for {
			req, err := http.ReadRequest(reader)
			if err != nil {
				return
			}
			u.requests <- req
			if u.responseGate != nil {
				<-u.responseGate
			}

			resp := &http.Response{
				StatusCode:    http.StatusOK,
				Status:        "200 OK",
				ProtoMajor:    1,
				ProtoMinor:    1,
				ContentLength: int64(len(u.responseBody)),
				Header: http.Header{
					"Content-Length": []string{fmt.Sprintf("%d", len(u.responseBody))},
				},
				Body: io.NopCloser(strings.NewReader(u.responseBody)),
			}
			if requestWantsClose(req) {
				resp.Close = true
				resp.Header.Set("Connection", "close")
			}
			if err := resp.Write(serverConn); err != nil {
				return
			}
			if requestWantsClose(req) {
				return
			}
		}
	}()
	return clientConn
}

func (u *recordingUpstream) dialHTTP2TLS(serverName string) (net.Conn, error) {
	clientConn, serverConn := net.Pipe()
	leaf, err := u.leafCertificates.CertificateForHost(serverName)
	if err != nil {
		_ = clientConn.Close()
		_ = serverConn.Close()
		return nil, err
	}

	serverTLS := tls.Server(serverConn, &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
	})
	clientTLS := tls.Client(clientConn, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		NextProtos:         []string{"h2", "http/1.1"},
	})

	go func() {
		if err := serverTLS.Handshake(); err != nil {
			_ = serverTLS.Close()
			return
		}
		http2Server := &http2.Server{}
		http2Server.ServeConn(serverTLS, &http2.ServeConnOpts{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				u.requests <- req.Clone(req.Context())
				if u.responseGate != nil {
					<-u.responseGate
				}
				w.Header().Set("Content-Length", fmt.Sprintf("%d", len(u.responseBody)))
				_, _ = io.WriteString(w, u.responseBody)
			}),
		})
	}()

	if err := clientTLS.Handshake(); err != nil {
		_ = clientTLS.Close()
		return nil, err
	}
	if clientTLS.ConnectionState().NegotiatedProtocol != "h2" {
		_ = clientTLS.Close()
		return nil, fmt.Errorf("negotiated upstream protocol %q, want h2", clientTLS.ConnectionState().NegotiatedProtocol)
	}
	return clientTLS, nil
}

func (u *recordingUpstream) dialRaw(context.Context, netip.AddrPort) (net.Conn, error) {
	clientConn, serverConn := net.Pipe()
	go func() {
		defer serverConn.Close()
		buf := make([]byte, 64)
		_, _ = serverConn.Read(buf)
		if u.rawReply != "" {
			_, _ = io.WriteString(serverConn, u.rawReply)
		}
	}()
	return clientConn, nil
}

func (u *recordingUpstream) dialCount() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.dialCalls
}

func newProxyTestAuthority(t *testing.T) *Authority {
	t.Helper()

	key, cert, _, _, err := newSelfSignedCA(func() time.Time {
		return time.Now().UTC()
	})
	if err != nil {
		t.Fatalf("newSelfSignedCA() error = %v", err)
	}
	return &Authority{
		Cert: cert,
		Key:  key,
	}
}

func testLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewTextHandler(&buf, nil)), &buf
}
