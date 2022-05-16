/*
 * Copyright (C) 2021 Nuts community
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

package core

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// MinTLSVersion defines the minimal TLS version used by all components that use TLS
const MinTLSVersion uint16 = tls.VersionTLS12

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

// TrustStore contains both a CertPool and the actual certificates
type TrustStore struct {
	CertPool     *x509.CertPool
	certificates []*x509.Certificate
}

// Certificates returns a copy of the certificates within the CertPool
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
