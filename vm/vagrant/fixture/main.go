package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	tcpEchoPort = 18081
	udpEchoPort = 18082
)

func main() {
	listen := flag.String("listen", "192.168.56.1:18080", "listen address")
	httpsPorts := flag.String("https-ports", "443,8443", "comma-separated HTTPS listen ports")
	readyFile := flag.String("ready-file", "", "path to write once the listener is ready")
	flag.Parse()

	host, _, err := net.SplitHostPort(*listen)
	if err != nil {
		log.Fatal(err)
	}
	ports, err := parsePortList(*httpsPorts)
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok\n")
	})

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	tcpEchoLn, err := net.Listen("tcp", net.JoinHostPort(host, fmt.Sprintf("%d", tcpEchoPort)))
	if err != nil {
		_ = ln.Close()
		log.Fatal(err)
	}
	udpEchoPC, err := net.ListenPacket("udp", net.JoinHostPort(host, fmt.Sprintf("%d", udpEchoPort)))
	if err != nil {
		_ = tcpEchoLn.Close()
		_ = ln.Close()
		log.Fatal(err)
	}
	httpsListeners, err := listenHTTPS(host, ports)
	if err != nil {
		_ = udpEchoPC.Close()
		_ = tcpEchoLn.Close()
		_ = ln.Close()
		log.Fatal(err)
	}

	cert, err := generateSelfSignedServerCert(host)
	if err != nil {
		closeAllListeners(httpsListeners)
		_ = udpEchoPC.Close()
		_ = tcpEchoLn.Close()
		_ = ln.Close()
		log.Fatal(err)
	}

	if err := writeReadyFile(*readyFile); err != nil {
		closeAllListeners(httpsListeners)
		_ = udpEchoPC.Close()
		_ = tcpEchoLn.Close()
		_ = ln.Close()
		log.Fatal(err)
	}

	server := &http.Server{Handler: mux}
	errCh := make(chan error, 3+len(httpsListeners))
	go serveTCPEcho(tcpEchoLn, errCh)
	go serveUDPEcho(udpEchoPC, errCh)
	go serveServer(server, ln, false, errCh)
	for _, httpsLn := range httpsListeners {
		httpsServer := &http.Server{
			Handler:   mux,
			TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		}
		go serveServer(httpsServer, httpsLn, true, errCh)
	}

	log.Printf("fixture ready: http=%s tcp-echo=%s udp-echo=%s https=%s", *listen, tcpEchoLn.Addr(), udpEchoPC.LocalAddr(), formatPorts(ports))
	if err := <-errCh; err != nil {
		log.Fatal(err)
	}
}

func parsePortList(raw string) ([]int, error) {
	parts := strings.Split(raw, ",")
	ports := make([]int, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("empty port in %q", raw)
		}
		port, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("parse port %q: %w", part, err)
		}
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("port %d out of range", port)
		}
		ports = append(ports, port)
	}
	return ports, nil
}

func listenHTTPS(host string, ports []int) ([]net.Listener, error) {
	listeners := make([]net.Listener, 0, len(ports))
	for _, port := range ports {
		ln, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
		if err != nil {
			closeAllListeners(listeners)
			return nil, err
		}
		listeners = append(listeners, ln)
	}
	return listeners, nil
}

func closeAllListeners(listeners []net.Listener) {
	for _, ln := range listeners {
		_ = ln.Close()
	}
}

func formatPorts(ports []int) string {
	values := make([]string, 0, len(ports))
	for _, port := range ports {
		values = append(values, strconv.Itoa(port))
	}
	return strings.Join(values, ",")
}

func writeReadyFile(path string) error {
	if path == "" {
		return nil
	}

	tmpPath := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".tmp")
	if err := os.WriteFile(tmpPath, []byte("ready\n"), 0o600); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func serveServer(server *http.Server, ln net.Listener, tlsMode bool, errCh chan<- error) {
	var err error
	if tlsMode {
		err = server.ServeTLS(ln, "", "")
	} else {
		err = server.Serve(ln)
	}
	if err != nil && err != http.ErrServerClosed {
		errCh <- err
	}
}

func serveTCPEcho(ln net.Listener, errCh chan<- error) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if isClosedErr(err) {
				return
			}
			errCh <- fmt.Errorf("accept tcp echo: %w", err)
			return
		}
		go func(conn net.Conn) {
			defer conn.Close()
			buf := make([]byte, 2048)
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			_, _ = conn.Write(buf[:n])
		}(conn)
	}
}

func serveUDPEcho(pc net.PacketConn, errCh chan<- error) {
	buf := make([]byte, 2048)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if isClosedErr(err) {
				return
			}
			errCh <- fmt.Errorf("read udp echo: %w", err)
			return
		}
		if _, err := pc.WriteTo(buf[:n], addr); err != nil && !isClosedErr(err) {
			errCh <- fmt.Errorf("write udp echo: %w", err)
			return
		}
	}
}

func isClosedErr(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "use of closed network connection")
}

func generateSelfSignedServerCert(host string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate serial: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create certificate: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("marshal key: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("load key pair: %w", err)
	}
	return cert, nil
}
