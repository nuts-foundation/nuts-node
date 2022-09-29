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

package x509

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

func createTestCert(parent, template *x509.Certificate, pubKey *rsa.PublicKey, caKey *rsa.PrivateKey) (*x509.Certificate, error) {
	if parent == nil {
		parent = template
	}

	derCert, err := x509.CreateCertificate(rand.Reader, template, parent, pubKey, caKey)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(derCert)
}

func createTestRootCert() (*x509.Certificate, *rsa.PrivateKey, error) {
	return createTestRootCertWithCrl("")
}

func createTestRootCertWithCrl(crlUrl string) (*x509.Certificate, *rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, nil, err
	}

	randSerial, _ := rand.Int(rand.Reader, big.NewInt(big.MaxExp))
	template := &x509.Certificate{
		SerialNumber: randSerial,
		NotBefore:    time.Now().Add(-10 * time.Second),
		NotAfter:     time.Now().Add(24 * time.Hour),
		Subject: pkix.Name{
			Country:      []string{"NL"},
			Organization: []string{"Nuts"},
			CommonName:   "Nuts Test - Root CA",
		},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign,
		MaxPathLen:            2,
	}

	cert, err := createTestCert(nil, template, &priv.PublicKey, priv)
	return cert, priv, err
}

func createIntermediateCert(parent *x509.Certificate, caKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey, error) {
	return createIntermediateCertWithCrl(parent, caKey, "")
}

func createIntermediateCertWithCrl(parent *x509.Certificate, caKey *rsa.PrivateKey, crlUrl string) (*x509.Certificate, *rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, nil, err
	}

	crlUrls := []string{}
	if len(crlUrl) > 0 {
		crlUrls = append(crlUrls, crlUrl)
	}
	randSerial, _ := rand.Int(rand.Reader, big.NewInt(big.MaxExp))
	template := &x509.Certificate{
		SerialNumber: randSerial,
		NotBefore:    time.Now().Add(-10 * time.Second),
		NotAfter:     time.Now().Add(24 * time.Hour),
		Subject: pkix.Name{
			Country:      []string{"NL"},
			Organization: []string{"Nuts"},
			CommonName:   "Nuts Test - Intermediate CA",
		},
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		MaxPathLen:            2,
		MaxPathLenZero:        false,
		CRLDistributionPoints: crlUrls,
	}
	cert, err := createTestCert(parent, template, &priv.PublicKey, caKey)
	return cert, priv, err
}
func createLeafCert(parent *x509.Certificate, caKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, nil, err
	}

	randSerial, _ := rand.Int(rand.Reader, big.NewInt(big.MaxExp))
	template := &x509.Certificate{
		SerialNumber: randSerial,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		Subject: pkix.Name{
			Country:    []string{"NL"},
			CommonName: "Henk de Vries",
		},
	}
	cert, err := createTestCert(parent, template, &priv.PublicKey, caKey)
	return cert, priv, err
}
