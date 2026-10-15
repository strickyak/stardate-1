package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// GenerateSelfSignedCert generates a self-signed ECDSA certificate and returns
// the tls.Certificate along with the PEM-encoded certificate and private key bytes.
func GenerateSelfSignedCert(hosts []string) (tls.Certificate, []byte, []byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Stardate"},
			CommonName:   "localhost",
		},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if len(hosts) == 0 {
		hosts = []string{"localhost", "127.0.0.1", "::1"}
	}

	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("failed to marshal EC private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("failed to create tls.Certificate: %w", err)
	}

	return tlsCert, certPEM, keyPEM, nil
}

// LoadOrGenerateCert loads a certificate and key from files if both exist.
// If both paths are provided but files do not exist, it generates self-signed certs
// and writes them to the specified files.
// If either path is empty, it generates an in-memory self-signed certificate.
func LoadOrGenerateCert(certPath, keyPath string, hosts []string) (tls.Certificate, error) {
	if certPath != "" && keyPath != "" {
		certExists := fileExists(certPath)
		keyExists := fileExists(keyPath)

		if certExists && keyExists {
			cert, err := tls.LoadX509KeyPair(certPath, keyPath)
			if err != nil {
				return tls.Certificate{}, fmt.Errorf("failed to load key pair from %s and %s: %w", certPath, keyPath, err)
			}
			return cert, nil
		}

		if certExists != keyExists {
			return tls.Certificate{}, fmt.Errorf("inconsistent TLS files: cert exists=%v, key exists=%v", certExists, keyExists)
		}

		// Neither exists: generate and save to disk
		tlsCert, certPEM, keyPEM, err := GenerateSelfSignedCert(hosts)
		if err != nil {
			return tls.Certificate{}, err
		}

		if err := writeCertFiles(certPath, keyPath, certPEM, keyPEM); err != nil {
			return tls.Certificate{}, fmt.Errorf("failed to write generated certificate to disk: %w", err)
		}

		return tlsCert, nil
	}

	// In-memory certificate only
	tlsCert, _, _, err := GenerateSelfSignedCert(hosts)
	return tlsCert, err
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func writeCertFiles(certPath, keyPath string, certPEM, keyPEM []byte) error {
	if err := os.MkdirAll(filepath.Dir(certPath), 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0755); err != nil {
		return err
	}
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return err
	}
	return nil
}
