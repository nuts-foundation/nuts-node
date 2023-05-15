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

// ParseCertificates reads PEM encoded X.509 certificates from the given input.
func ParseCertificates(data []byte) (certificates []*x509.Certificate, _ error) {
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

// NewCertPool creates a new x509.CertPool and adds all given certificates to it.
func NewCertPool(certificates []*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, certificate := range certificates {
		pool.AddCert(certificate)
	}
	return pool
}

// TrustStore contains both a CertPool and the actual certificates
type TrustStore struct {
	CertPool        *x509.CertPool
	RootCAs         []*x509.Certificate
	IntermediateCAs []*x509.Certificate
	certificates    []*x509.Certificate
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
	return ParseTrustStore(data)
}

// ParseTrustStore creates a x509 certificate pool from the raw data
func ParseTrustStore(data []byte) (*TrustStore, error) {
	var err error
	trustStore := new(TrustStore)

	trustStore.certificates, err = ParseCertificates(data)
	if err != nil {
		return nil, err
	}
	trustStore.CertPool = NewCertPool(trustStore.certificates)

	for _, certificate := range trustStore.certificates {
		// Certificate v1 don't have extensions and thus lack basicConstraints.IsCA, just check issuer == subject in that case.
		if certificate.IsCA || certificate.Version == 1 {
			if certificate.Subject.String() == certificate.Issuer.String() {
				trustStore.RootCAs = append(trustStore.RootCAs, certificate)
			} else {
				trustStore.IntermediateCAs = append(trustStore.IntermediateCAs, certificate)
			}
		}
	}

	if err = validate(trustStore); err != nil {
		return nil, err
	}

	return trustStore, nil
}

// validate returns an error if one of the certificates is invalid or does not form a chain to some root
func validate(store *TrustStore) error {
	opts := x509.VerifyOptions{
		Intermediates: NewCertPool(store.IntermediateCAs),
		Roots:         NewCertPool(store.RootCAs),
	}
	for _, cert := range store.Certificates() {
		// We do not want to validate the time on the certificate, so we set VerifyOptions.CurrentTime to something where
		// the certificate is guaranteed to be valid.
		opts.CurrentTime = cert.NotBefore
		if _, err := cert.Verify(opts); err != nil {
			return err
		}
	}
	return nil
}
