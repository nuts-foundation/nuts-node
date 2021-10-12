package core

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func parseCertificates(data []byte) (certificates []*x509.Certificate, _ error) {
	for len(data) > 0 {
		var block *pem.Block

		block, data = pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("unable to decode PEM encoded data")
		}

		if block.Type != "CERTIFICATE" {
			continue
		}

		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("unable to parse certificate: %w", err)
		}

		certificates = append(certificates, certificate)
	}

	return
}

type TrustStore struct {
	CertPool     *x509.CertPool
	certificates []*x509.Certificate
}

func (store *TrustStore) Certificates() []*x509.Certificate {
	return store.certificates[:]
}

// LoadTrustStore creates a x509 certificate pool based on a truststore file
func LoadTrustStore(trustStoreFile string) (*TrustStore, error) {
	data, err := os.ReadFile(trustStoreFile)
	if err != nil {
		return nil, fmt.Errorf("unable to read trust store (file=%s): %w", trustStoreFile, err)
	}

	certificates, err := parseCertificates(data)
	if err != nil {
		return nil, err
	}

	var (
		certPool = x509.NewCertPool()
	)

	for _, certificate := range certificates {
		certPool.AddCert(certificate)
	}

	return &TrustStore{
		CertPool:     certPool,
		certificates: certificates,
	}, nil
}
