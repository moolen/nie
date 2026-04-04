package mitm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

type CAPaths struct {
	CertFile string
	KeyFile  string
}

type Authority struct {
	Cert *x509.Certificate
	Key  crypto.Signer
}

func EnsureCA(paths CAPaths) (*Authority, error) {
	certExists, err := fileExists(paths.CertFile)
	if err != nil {
		return nil, fmt.Errorf("check cert file %q: %w", paths.CertFile, err)
	}
	keyExists, err := fileExists(paths.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("check key file %q: %w", paths.KeyFile, err)
	}

	switch {
	case certExists && keyExists:
		return loadAuthority(paths)
	case certExists != keyExists:
		return nil, fmt.Errorf(
			"incomplete CA material: cert exists=%t (%s), key exists=%t (%s)",
			certExists,
			paths.CertFile,
			keyExists,
			paths.KeyFile,
		)
	default:
		return generateAndPersistAuthority(paths)
	}
}

func fileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

func loadAuthority(paths CAPaths) (*Authority, error) {
	certPEM, err := os.ReadFile(paths.CertFile)
	if err != nil {
		return nil, fmt.Errorf("read cert file %q: %w", paths.CertFile, err)
	}
	keyPEM, err := os.ReadFile(paths.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("read key file %q: %w", paths.KeyFile, err)
	}

	cert, err := parseSingleCertificate(certPEM)
	if err != nil {
		return nil, fmt.Errorf("parse cert file %q: %w", paths.CertFile, err)
	}
	key, err := parseSigner(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse key file %q: %w", paths.KeyFile, err)
	}

	return &Authority{Cert: cert, Key: key}, nil
}

func generateAndPersistAuthority(paths CAPaths) (*Authority, error) {
	if err := os.MkdirAll(filepath.Dir(paths.CertFile), 0o755); err != nil {
		return nil, fmt.Errorf("create cert parent dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(paths.KeyFile), 0o755); err != nil {
		return nil, fmt.Errorf("create key parent dir: %w", err)
	}

	key, cert, certPEM, keyPEM, err := newSelfSignedCA(time.Now)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(paths.CertFile, certPEM, 0o600); err != nil {
		return nil, fmt.Errorf("write cert file %q: %w", paths.CertFile, err)
	}
	if err := os.WriteFile(paths.KeyFile, keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("write key file %q: %w", paths.KeyFile, err)
	}

	return &Authority{Cert: cert, Key: key}, nil
}

func newSelfSignedCA(nowFn func() time.Time) (*ecdsa.PrivateKey, *x509.Certificate, []byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("generate CA key: %w", err)
	}

	now := nowFn().UTC()
	serialNumber, err := randomSerial()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("generate CA serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "nie local MITM root",
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("create self-signed CA cert: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("parse self-signed CA cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("marshal CA private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return key, cert, certPEM, keyPEM, nil
}

func parseSingleCertificate(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("missing PEM CERTIFICATE block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func parseSigner(keyPEM []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("missing PEM private key block")
	}

	switch block.Type {
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		signer, ok := parsed.(crypto.Signer)
		if !ok {
			return nil, errors.New("PKCS8 key is not a signer")
		}
		return signer, nil
	default:
		return nil, fmt.Errorf("unsupported PEM key block type %q", block.Type)
	}
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}
