package core

import (
	"crypto/x509"
	"fmt"
	"os"
)

// LoadTrustStore creates a x509 certificate pool based on a truststore file
func LoadTrustStore(trustStoreFile string) (*x509.CertPool, error) {
	trustStore := x509.NewCertPool()
	data, err := os.ReadFile(trustStoreFile)
	if err != nil {
		return nil, fmt.Errorf("unable to read trust store (file=%s): %w", trustStoreFile, err)
	}
	if ok := trustStore.AppendCertsFromPEM(data); !ok {
		return nil, fmt.Errorf("unable to load one or more certificates from trust store (file=%s)", trustStoreFile)
	}
	return trustStore, nil
}
