package mitm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/moolen/nie/internal/policy"
)

type LeafCache struct {
	authority *Authority
	now       func() time.Time

	mu    sync.Mutex
	certs map[string]*tls.Certificate
}

func NewLeafCache(authority *Authority, now func() time.Time) *LeafCache {
	if now == nil {
		now = time.Now
	}

	return &LeafCache{
		authority: authority,
		now:       now,
		certs:     make(map[string]*tls.Certificate),
	}
}

func (c *LeafCache) CertificateForHost(host string) (*tls.Certificate, error) {
	if c == nil {
		return nil, errors.New("leaf cache must not be nil")
	}
	if c.authority == nil || c.authority.Cert == nil || c.authority.Key == nil {
		return nil, errors.New("authority must be fully initialized")
	}

	normalizedHost := policy.NormalizeHostname(host)
	if normalizedHost == "" {
		return nil, errors.New("host must not be empty after normalization")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if cert, ok := c.certs[normalizedHost]; ok {
		return cert, nil
	}

	cert, err := c.issueLeafCertificate(normalizedHost)
	if err != nil {
		return nil, err
	}
	c.certs[normalizedHost] = cert
	return cert, nil
}

func (c *LeafCache) issueLeafCertificate(host string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key for %q: %w", host, err)
	}

	now := c.now().UTC()
	serial, err := randomSerial()
	if err != nil {
		return nil, fmt.Errorf("generate leaf serial number for %q: %w", host, err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore: now.Add(-5 * time.Minute),
		NotAfter:  minTime(now.Add(90*24*time.Hour), c.authority.Cert.NotAfter),
		DNSNames:  []string{host},
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, template, c.authority.Cert, key.Public(), c.authority.Key)
	if err != nil {
		return nil, fmt.Errorf("create leaf certificate for %q: %w", host, err)
	}

	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, fmt.Errorf("parse leaf certificate for %q: %w", host, err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{leafDER, c.authority.Cert.Raw},
		PrivateKey:  key,
		Leaf:        leaf,
	}, nil
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
