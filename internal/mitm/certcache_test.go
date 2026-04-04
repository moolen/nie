package mitm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"slices"
	"testing"
	"time"
)

func TestLeafCache_IssuesCertificateForSNI(t *testing.T) {
	t.Parallel()

	authority := testAuthority(t)
	cache := NewLeafCache(authority, func() time.Time {
		return time.Date(2026, time.April, 4, 12, 0, 0, 0, time.UTC)
	})

	first, err := cache.CertificateForHost(" API.GitHub.Com. ")
	if err != nil {
		t.Fatalf("CertificateForHost() error = %v", err)
	}
	if first == nil || len(first.Certificate) == 0 {
		t.Fatal("CertificateForHost() returned empty certificate")
	}

	leaf, err := x509.ParseCertificate(first.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}
	if !slices.Contains(leaf.DNSNames, "api.github.com") {
		t.Fatalf("leaf DNSNames = %v, want %q", leaf.DNSNames, "api.github.com")
	}

	second, err := cache.CertificateForHost("api.github.com")
	if err != nil {
		t.Fatalf("CertificateForHost(second) error = %v", err)
	}
	if first != second {
		t.Fatal("CertificateForHost() did not cache by normalized hostname")
	}
}

func testAuthority(t *testing.T) *Authority {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	now := time.Date(2026, time.April, 4, 12, 0, 0, 0, time.UTC)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "nie leaf issuer test root",
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, key.Public(), key)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate(ca) error = %v", err)
	}

	return &Authority{
		Cert: cert,
		Key:  key,
	}
}
