package server

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateSelfSignedCert(t *testing.T) {
	hosts := []string{"localhost", "127.0.0.1", "example.com"}
	tlsCert, certPEM, keyPEM, err := GenerateSelfSignedCert(hosts)
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert failed: %v", err)
	}

	if len(tlsCert.Certificate) == 0 {
		t.Fatal("expected certificate in tlsCert, got none")
	}

	if len(certPEM) == 0 {
		t.Fatal("expected certPEM to be non-empty")
	}
	if len(keyPEM) == 0 {
		t.Fatal("expected keyPEM to be non-empty")
	}

	parsed, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatalf("failed to parse generated certificate: %v", err)
	}

	if parsed.Subject.CommonName != "localhost" {
		t.Errorf("expected CommonName 'localhost', got %q", parsed.Subject.CommonName)
	}

	foundDNS := false
	for _, dns := range parsed.DNSNames {
		if dns == "example.com" {
			foundDNS = true
			break
		}
	}
	if !foundDNS {
		t.Errorf("expected DNS 'example.com' in %v", parsed.DNSNames)
	}
}

func TestLoadOrGenerateCert(t *testing.T) {
	// Test in-memory generation
	cert, err := LoadOrGenerateCert("", "", nil)
	if err != nil {
		t.Fatalf("LoadOrGenerateCert (in-memory) failed: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("expected certificate in tlsCert, got none")
	}

	// Test file-based generation and re-loading inside local directory
	testDir := filepath.Join(".", ".test_tmp")
	_ = os.RemoveAll(testDir)
	defer os.RemoveAll(testDir)

	certPath := filepath.Join(testDir, "cert.pem")
	keyPath := filepath.Join(testDir, "key.pem")

	// First call should generate and save
	cert1, err := LoadOrGenerateCert(certPath, keyPath, []string{"localhost"})
	if err != nil {
		t.Fatalf("failed to generate and save cert: %v", err)
	}

	if !fileExists(certPath) || !fileExists(keyPath) {
		t.Fatalf("expected cert and key files to exist at %s and %s", certPath, keyPath)
	}

	// Second call should load existing
	cert2, err := LoadOrGenerateCert(certPath, keyPath, []string{"localhost"})
	if err != nil {
		t.Fatalf("failed to load existing cert: %v", err)
	}

	if len(cert1.Certificate[0]) != len(cert2.Certificate[0]) {
		t.Errorf("expected loaded cert to match generated cert length")
	}
}
