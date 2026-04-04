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
	"strings"
	"time"
)

const (
	tcpEchoPort = 18081
	udpEchoPort = 18082
)

func main() {
	listen := flag.String("listen", "192.168.56.1:18080", "listen address")
	readyFile := flag.String("ready-file", "", "path to write once the listener is ready")
	flag.Parse()

	host, _, err := net.SplitHostPort(*listen)
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
	https443Ln, err := net.Listen("tcp", net.JoinHostPort(host, "443"))
	if err != nil {
		_ = udpEchoPC.Close()
		_ = tcpEchoLn.Close()
		_ = ln.Close()
		log.Fatal(err)
	}
	https8443Ln, err := net.Listen("tcp", net.JoinHostPort(host, "8443"))
	if err != nil {
		_ = https443Ln.Close()
		_ = udpEchoPC.Close()
		_ = tcpEchoLn.Close()
		_ = ln.Close()
		log.Fatal(err)
	}

	cert, err := generateSelfSignedServerCert(host)
	if err != nil {
		_ = https8443Ln.Close()
		_ = https443Ln.Close()
		_ = udpEchoPC.Close()
		_ = tcpEchoLn.Close()
		_ = ln.Close()
		log.Fatal(err)
	}

	if err := writeReadyFile(*readyFile); err != nil {
		_ = https8443Ln.Close()
		_ = https443Ln.Close()
		_ = udpEchoPC.Close()
		_ = tcpEchoLn.Close()
		_ = ln.Close()
		log.Fatal(err)
	}

	server := &http.Server{Handler: mux}
	https443Server := &http.Server{
		Handler:   mux,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
	}
	https8443Server := &http.Server{
		Handler:   mux,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
	}

	errCh := make(chan error, 5)
	go serveTCPEcho(tcpEchoLn, errCh)
	go serveUDPEcho(udpEchoPC, errCh)
	go serveServer(server, ln, false, errCh)
	go serveServer(https443Server, https443Ln, true, errCh)
	go serveServer(https8443Server, https8443Ln, true, errCh)

	log.Printf("fixture ready: http=%s tcp-echo=%s udp-echo=%s https=443,8443", *listen, tcpEchoLn.Addr(), udpEchoPC.LocalAddr())
	if err := <-errCh; err != nil {
		log.Fatal(err)
	}
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
