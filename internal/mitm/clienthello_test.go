package mitm

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"testing"
)

func TestParseClientHelloSNI(t *testing.T) {
	record := captureClientHelloRecord(t, "api.github.com")

	hello, err := parseClientHello(record)
	if err != nil {
		t.Fatalf("parseClientHello() error = %v", err)
	}
	if hello.ServerName != "api.github.com" {
		t.Fatalf("ClientHello.ServerName = %q, want api.github.com", hello.ServerName)
	}
}

func TestParseClientHelloMissingSNI(t *testing.T) {
	record := captureClientHelloRecord(t, "")

	_, err := parseClientHello(record)
	if !errors.Is(err, ErrClientHelloMissingSNI) {
		t.Fatalf("parseClientHello() error = %v, want %v", err, ErrClientHelloMissingSNI)
	}
}

func TestPeekClientHelloPreservesBytes(t *testing.T) {
	record := captureClientHelloRecord(t, "api.github.com")

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	writeErr := make(chan error, 1)
	go func() {
		_, err := clientConn.Write(record)
		_ = clientConn.Close()
		writeErr <- err
		close(writeErr)
	}()

	buffered, hello, err := PeekClientHello(serverConn)
	if err != nil {
		t.Fatalf("PeekClientHello() error = %v", err)
	}
	if hello.ServerName != "api.github.com" {
		t.Fatalf("ClientHello.ServerName = %q, want api.github.com", hello.ServerName)
	}

	got, err := io.ReadAll(buffered)
	if err != nil {
		t.Fatalf("io.ReadAll(buffered) error = %v", err)
	}
	if !bytes.Equal(got, record) {
		t.Fatalf("buffered bytes changed:\n got %x\nwant %x", got, record)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("client write error = %v", err)
	}
}

func captureClientHelloRecord(t *testing.T, serverName string) []byte {
	t.Helper()

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	handshakeErr := make(chan error, 1)
	go func() {
		cfg := &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         serverName,
		}
		handshakeErr <- tls.Client(clientConn, cfg).Handshake()
	}()

	record := readTLSRecord(t, serverConn)
	serverConn.Close()

	if err := <-handshakeErr; err == nil {
		t.Fatal("client handshake error = nil, want handshake to stop after captured ClientHello")
	}

	return record
}

func readTLSRecord(t *testing.T, conn net.Conn) []byte {
	t.Helper()

	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		t.Fatalf("read TLS record header: %v", err)
	}
	length := int(header[3])<<8 | int(header[4])
	record := make([]byte, len(header)+length)
	copy(record, header)
	if _, err := io.ReadFull(conn, record[len(header):]); err != nil {
		t.Fatalf("read TLS record payload: %v", err)
	}
	return record
}
