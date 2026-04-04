package mitm

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
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
