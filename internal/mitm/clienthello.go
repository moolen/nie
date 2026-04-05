package mitm

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

var ErrClientHelloMissingSNI = errors.New("tls client hello does not include sni")
var ErrClientHelloTooLarge = errors.New("tls client hello exceeds configured limit")

const defaultClientHelloMaxBytes = 64 << 10

type BufferedConn interface {
	net.Conn
}

type ClientHello struct {
	ServerName string
}

func PeekClientHello(conn net.Conn) (BufferedConn, ClientHello, error) {
	return PeekClientHelloWithLimit(conn, defaultClientHelloMaxBytes)
}

func PeekClientHelloWithLimit(conn net.Conn, maxBytes int) (BufferedConn, ClientHello, error) {
	if conn == nil {
		return nil, ClientHello{}, errors.New("connection must not be nil")
	}
	if maxBytes <= 0 {
		maxBytes = defaultClientHelloMaxBytes
	}

	reader := bufio.NewReader(conn)
	recordBytes, err := readClientHelloRecords(reader, maxBytes)
	buffered := &bufferedConn{Conn: conn, reader: reader}
	if err != nil {
		return buffered, ClientHello{}, err
	}
	buffered.reader = io.MultiReader(bytes.NewReader(recordBytes), reader)

	hello, parseErr := parseClientHello(recordBytes)
	return buffered, hello, parseErr
}

type bufferedConn struct {
	net.Conn
	reader io.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func readClientHelloRecords(reader *bufio.Reader, maxBytes int) ([]byte, error) {
	var records bytes.Buffer
	var handshake bytes.Buffer

	for {
		record, err := readTLSRecordBytes(reader, maxBytes, records.Len())
		if err != nil {
			return nil, err
		}
		records.Write(record)

		if record[0] != 22 {
			return nil, fmt.Errorf("unexpected tls record type %d", record[0])
		}

		payload := record[5:]
		handshake.Write(payload)
		if handshake.Len() < 4 {
			continue
		}

		handshakeBytes := handshake.Bytes()
		if handshakeBytes[0] != 1 {
			return nil, fmt.Errorf("unexpected tls handshake type %d", handshakeBytes[0])
		}

		needed := 4 + int(handshakeBytes[1])<<16 + int(handshakeBytes[2])<<8 + int(handshakeBytes[3])
		if needed > maxBytes {
			return nil, ErrClientHelloTooLarge
		}
		if handshake.Len() >= needed {
			return records.Bytes(), nil
		}
	}
}

func readTLSRecordBytes(reader *bufio.Reader, maxBytes, bufferedBytes int) ([]byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, fmt.Errorf("read tls record header: %w", err)
	}

	length := int(binary.BigEndian.Uint16(header[3:5]))
	if bufferedBytes+len(header)+length > maxBytes {
		return nil, ErrClientHelloTooLarge
	}
	record := make([]byte, len(header)+length)
	copy(record, header)
	if _, err := io.ReadFull(reader, record[len(header):]); err != nil {
		return nil, fmt.Errorf("read tls record payload: %w", err)
	}
	return record, nil
}

func parseClientHello(data []byte) (ClientHello, error) {
	handshake, err := clientHelloHandshake(data)
	if err != nil {
		return ClientHello{}, err
	}
	if len(handshake) < 4 {
		return ClientHello{}, io.ErrUnexpectedEOF
	}
	if handshake[0] != 1 {
		return ClientHello{}, fmt.Errorf("unexpected tls handshake type %d", handshake[0])
	}

	body := handshake[4:]
	serverName, err := parseClientHelloServerName(body)
	if err != nil {
		return ClientHello{}, err
	}
	return ClientHello{ServerName: serverName}, nil
}

func clientHelloHandshake(data []byte) ([]byte, error) {
	var handshake bytes.Buffer

	for len(data) > 0 {
		if len(data) < 5 {
			return nil, io.ErrUnexpectedEOF
		}
		length := int(binary.BigEndian.Uint16(data[3:5]))
		recordLen := 5 + length
		if len(data) < recordLen {
			return nil, io.ErrUnexpectedEOF
		}
		if data[0] != 22 {
			return nil, fmt.Errorf("unexpected tls record type %d", data[0])
		}

		handshake.Write(data[5:recordLen])
		if handshake.Len() >= 4 {
			handshakeBytes := handshake.Bytes()
			if handshakeBytes[0] != 1 {
				return nil, fmt.Errorf("unexpected tls handshake type %d", handshakeBytes[0])
			}
			needed := 4 + int(handshakeBytes[1])<<16 + int(handshakeBytes[2])<<8 + int(handshakeBytes[3])
			if handshake.Len() >= needed {
				return append([]byte(nil), handshakeBytes[:needed]...), nil
			}
		}

		data = data[recordLen:]
	}

	return nil, io.ErrUnexpectedEOF
}

func parseClientHelloServerName(body []byte) (string, error) {
	if len(body) < 34 {
		return "", io.ErrUnexpectedEOF
	}

	offset := 2 + 32

	sessionIDLen, next, err := readUint8Vector(body, offset)
	if err != nil {
		return "", err
	}
	offset = next + sessionIDLen
	if offset > len(body) {
		return "", io.ErrUnexpectedEOF
	}

	cipherSuitesLen, next, err := readUint16Vector(body, offset)
	if err != nil {
		return "", err
	}
	offset = next + cipherSuitesLen
	if offset > len(body) {
		return "", io.ErrUnexpectedEOF
	}

	compressionMethodsLen, next, err := readUint8Vector(body, offset)
	if err != nil {
		return "", err
	}
	offset = next + compressionMethodsLen
	if offset > len(body) {
		return "", io.ErrUnexpectedEOF
	}

	if offset == len(body) {
		return "", ErrClientHelloMissingSNI
	}

	extensionsLen, extensionsOffset, err := readUint16Vector(body, offset)
	if err != nil {
		return "", err
	}
	extensionsEnd := extensionsOffset + extensionsLen
	if extensionsEnd > len(body) {
		return "", io.ErrUnexpectedEOF
	}

	for offset = extensionsOffset; offset < extensionsEnd; {
		if offset+4 > extensionsEnd {
			return "", io.ErrUnexpectedEOF
		}

		extensionType := binary.BigEndian.Uint16(body[offset : offset+2])
		extensionLen := int(binary.BigEndian.Uint16(body[offset+2 : offset+4]))
		offset += 4

		if offset+extensionLen > extensionsEnd {
			return "", io.ErrUnexpectedEOF
		}
		extensionData := body[offset : offset+extensionLen]
		offset += extensionLen

		if extensionType != 0 {
			continue
		}

		serverName, err := parseServerNameExtension(extensionData)
		if err != nil {
			return "", err
		}
		if serverName == "" {
			return "", ErrClientHelloMissingSNI
		}
		return serverName, nil
	}

	return "", ErrClientHelloMissingSNI
}

func parseServerNameExtension(data []byte) (string, error) {
	if len(data) < 2 {
		return "", io.ErrUnexpectedEOF
	}

	listLen := int(binary.BigEndian.Uint16(data[:2]))
	if len(data) < 2+listLen {
		return "", io.ErrUnexpectedEOF
	}

	for offset := 2; offset < 2+listLen; {
		if offset+3 > len(data) {
			return "", io.ErrUnexpectedEOF
		}

		nameType := data[offset]
		nameLen := int(binary.BigEndian.Uint16(data[offset+1 : offset+3]))
		offset += 3

		if offset+nameLen > len(data) {
			return "", io.ErrUnexpectedEOF
		}
		name := data[offset : offset+nameLen]
		offset += nameLen

		if nameType == 0 {
			return string(name), nil
		}
	}

	return "", nil
}

func readUint8Vector(data []byte, offset int) (length int, next int, err error) {
	if offset >= len(data) {
		return 0, 0, io.ErrUnexpectedEOF
	}
	return int(data[offset]), offset + 1, nil
}

func readUint16Vector(data []byte, offset int) (length int, next int, err error) {
	if offset+2 > len(data) {
		return 0, 0, io.ErrUnexpectedEOF
	}
	return int(binary.BigEndian.Uint16(data[offset : offset+2])), offset + 2, nil
}
