package kryptograf

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"os"
)

// CertificateIDsFromPEM parses PEM-encoded data and returns a slice of
// certificate identifiers. Each identifier is the hex-encoded SHA-256 hash of
// the certificate's DER encoding.
func CertificateIDsFromPEM(data []byte) ([]string, error) {
	var ids []string
	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("kryptograf: invalid PEM data")
		}
		data = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("kryptograf: parse certificate: %w", err)
		}
		sum := sha256.Sum256(cert.Raw)
		ids = append(ids, hex.EncodeToString(sum[:]))
	}
	return ids, nil
}

// CertificateIDsFromReader reads PEM data from r and returns certificate
// identifiers as produced by CertificateIDsFromPEM.
func CertificateIDsFromReader(r io.Reader) ([]string, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("kryptograf: read PEM data: %w", err)
	}
	return CertificateIDsFromPEM(data)
}

// CertificateIDsFromFile loads the PEM file at path and returns certificate
// identifiers as produced by CertificateIDsFromPEM.
func CertificateIDsFromFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("kryptograf: read PEM file: %w", err)
	}
	return CertificateIDsFromPEM(data)
}
