/*
 * Copyright (C) 2023 Nuts community
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

package pki

import (
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"github.com/nuts-foundation/nuts-node/test/io"
	"os"
	"path"
	"testing"
)

// CertificateData contains the PEM-encoded test certificate and its key.
//
//go:embed certificate-and-key.pem
var CertificateData []byte

// InvalidCertificateData contains the PEM-encoded invalid test certificate and its key.
//
//go:embed invalid-cert.pem
var InvalidCertificateData []byte

// TruststoreData contains the PEM-encoded test truststore.
//
//go:embed truststore.pem
var TruststoreData []byte

// CertificateFile returns the path to a file containing a valid test certificate and its key.
func CertificateFile(t *testing.T) string {
	return writeToTemp(t, "certificate.pem", CertificateData)
}

// InvalidCertificate returns an invalid test certificate.
func InvalidCertificate() tls.Certificate {
	cert, err := tls.X509KeyPair(InvalidCertificateData, InvalidCertificateData)
	if err != nil {
		panic(err)
	}
	cert.Leaf, _ = x509.ParseCertificate(cert.Certificate[0])
	return cert
}

// Certificate returns a valid test certificate.
func Certificate() tls.Certificate {
	cert, err := tls.X509KeyPair(CertificateData, CertificateData)
	if err != nil {
		panic(err)
	}
	cert.Leaf, _ = x509.ParseCertificate(cert.Certificate[0])
	return cert
}

// TruststoreFile returns the path to a file containing a test truststore.
func TruststoreFile(t *testing.T) string {
	return writeToTemp(t, "truststore.pem", TruststoreData)
}

// Truststore returns a test truststore.
func Truststore() *x509.CertPool {
	pool := x509.NewCertPool()
	ok := pool.AppendCertsFromPEM(TruststoreData)
	if !ok {
		panic("failed to parse root certificate")
	}
	return pool
}

func writeToTemp(t *testing.T, fileName string, data []byte) string {
	filePath := path.Join(io.TestDirectory(t), fileName)
	err := os.WriteFile(filePath, data, os.ModePerm)
	if err != nil {
		t.Fatal(err)
	}
	return filePath
}
