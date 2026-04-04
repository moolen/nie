package mitm

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEnsureCA_GeneratesFilesWhenMissing(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	paths := CAPaths{
		CertFile: filepath.Join(root, "nested", "root.crt"),
		KeyFile:  filepath.Join(root, "nested", "root.key"),
	}

	authority, err := EnsureCA(paths)
	if err != nil {
		t.Fatalf("EnsureCA() error = %v", err)
	}
	if authority == nil || authority.Cert == nil || authority.Key == nil {
		t.Fatal("EnsureCA() returned incomplete authority")
	}

	certBytes, err := os.ReadFile(paths.CertFile)
	if err != nil {
		t.Fatalf("ReadFile(cert) error = %v", err)
	}
	keyBytes, err := os.ReadFile(paths.KeyFile)
	if err != nil {
		t.Fatalf("ReadFile(key) error = %v", err)
	}
	if len(certBytes) == 0 || len(keyBytes) == 0 {
		t.Fatal("EnsureCA() did not persist CA material")
	}

	assertRestrictivePermissions(t, paths.CertFile)
	assertRestrictivePermissions(t, paths.KeyFile)
}

func TestEnsureCA_ReusesExistingFiles(t *testing.T) {
	t.Parallel()

	certPEM, keyPEM := generateTestCAPEM(t)
	root := t.TempDir()
	paths := CAPaths{
		CertFile: filepath.Join(root, "ca", "root.crt"),
		KeyFile:  filepath.Join(root, "ca", "root.key"),
	}
	if err := os.MkdirAll(filepath.Dir(paths.CertFile), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(paths.CertFile, certPEM, 0o600); err != nil {
		t.Fatalf("WriteFile(cert) error = %v", err)
	}
	if err := os.WriteFile(paths.KeyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("WriteFile(key) error = %v", err)
	}

	authority, err := EnsureCA(paths)
	if err != nil {
		t.Fatalf("EnsureCA() error = %v", err)
	}
	if authority == nil || authority.Cert == nil || authority.Key == nil {
		t.Fatal("EnsureCA() returned incomplete authority")
	}

	gotCert, err := os.ReadFile(paths.CertFile)
	if err != nil {
		t.Fatalf("ReadFile(cert) error = %v", err)
	}
	gotKey, err := os.ReadFile(paths.KeyFile)
	if err != nil {
		t.Fatalf("ReadFile(key) error = %v", err)
	}
	if !bytes.Equal(gotCert, certPEM) {
		t.Fatal("EnsureCA() rewrote existing cert file")
	}
	if !bytes.Equal(gotKey, keyPEM) {
		t.Fatal("EnsureCA() rewrote existing key file")
	}
}

func TestEnsureCA_FailsWhenExactlyOneFileExists(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		writeCert bool
		writeKey  bool
	}{
		{
			name:      "only cert exists",
			writeCert: true,
			writeKey:  false,
		},
		{
			name:      "only key exists",
			writeCert: false,
			writeKey:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			certPEM, keyPEM := generateTestCAPEM(t)
			paths := CAPaths{
				CertFile: filepath.Join(root, "ca", "root.crt"),
				KeyFile:  filepath.Join(root, "ca", "root.key"),
			}
			if err := os.MkdirAll(filepath.Dir(paths.CertFile), 0o755); err != nil {
				t.Fatalf("MkdirAll() error = %v", err)
			}
			if tt.writeCert {
				if err := os.WriteFile(paths.CertFile, certPEM, 0o600); err != nil {
					t.Fatalf("WriteFile(cert) error = %v", err)
				}
			}
			if tt.writeKey {
				if err := os.WriteFile(paths.KeyFile, keyPEM, 0o600); err != nil {
					t.Fatalf("WriteFile(key) error = %v", err)
				}
			}

			_, err := EnsureCA(paths)
			if err == nil {
				t.Fatal("EnsureCA() error = nil, want non-nil")
			}
			if !strings.Contains(err.Error(), "incomplete CA material") {
				t.Fatalf("EnsureCA() error = %q, want incomplete CA material context", err)
			}
		})
	}
}

func TestEnsureCA_RejectsInvalidCAOrMismatchedKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		certPEM   []byte
		keyPEM    []byte
		wantError string
	}{
		{
			name:      "rejects non-ca certificate",
			certPEM:   mustGenerateLeafCertPEM(t),
			keyPEM:    mustGenerateECDSAKeyPEM(t),
			wantError: "not a certificate authority",
		},
		{
			name:      "rejects key mismatch",
			certPEM:   mustGenerateSelfSignedCACertPEM(t),
			keyPEM:    mustGenerateRSAKeyPEM(t),
			wantError: "does not match certificate public key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			paths := CAPaths{
				CertFile: filepath.Join(root, "ca", "root.crt"),
				KeyFile:  filepath.Join(root, "ca", "root.key"),
			}
			if err := os.MkdirAll(filepath.Dir(paths.CertFile), 0o755); err != nil {
				t.Fatalf("MkdirAll() error = %v", err)
			}
			if err := os.WriteFile(paths.CertFile, tt.certPEM, 0o600); err != nil {
				t.Fatalf("WriteFile(cert) error = %v", err)
			}
			if err := os.WriteFile(paths.KeyFile, tt.keyPEM, 0o600); err != nil {
				t.Fatalf("WriteFile(key) error = %v", err)
			}

			_, err := EnsureCA(paths)
			if err == nil {
				t.Fatal("EnsureCA() error = nil, want non-nil")
			}
			if !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("EnsureCA() error = %q, want substring %q", err, tt.wantError)
			}
		})
	}
}

func generateTestCAPEM(t *testing.T) ([]byte, []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	now := time.Date(2026, time.April, 4, 12, 0, 0, 0, time.UTC)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "nie test root",
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

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey() error = %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

func mustGenerateSelfSignedCACertPEM(t *testing.T) []byte {
	t.Helper()
	certPEM, _ := generateTestCAPEM(t)
	return certPEM
}

func mustGenerateLeafCertPEM(t *testing.T) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	now := time.Date(2026, time.April, 4, 12, 0, 0, 0, time.UTC)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject: pkix.Name{
			CommonName: "not-a-ca",
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, key.Public(), key)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func mustGenerateECDSAKeyPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey() error = %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

func mustGenerateRSAKeyPEM(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

func assertRestrictivePermissions(t *testing.T, path string) {
	t.Helper()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%q) error = %v", path, err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("permissions for %s = %o, want no group/other bits set", path, info.Mode().Perm())
	}
}
