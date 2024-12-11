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
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"encoding/asn1"
	"encoding/base64"
	"github.com/lestrrat-go/jwx/v2/cert"
	"github.com/nuts-foundation/nuts-node/test/io"
	"math/big"
	"net"
	"os"
	"path"
	"testing"
	"time"
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

func CertsToChain(certs []*x509.Certificate) *cert.Chain {
	result := new(cert.Chain)
	for _, c := range certs {
		_ = result.Add([]byte(base64.StdEncoding.EncodeToString(c.Raw)))
	}
	return result
}

// BuildCertChain generates a certificate chain, including root, intermediate, and signing certificates.
func BuildCertChain(identifiers []string, subjectSerialNumber string) ([]*x509.Certificate, []*rsa.PrivateKey, error) {
	rootKey, rootCert, err := BuildRootCert()
	if err != nil {
		return nil, nil, err
	}
	intermediateL1Key, intermediateL1Cert, err := buildIntermediateCert(rootCert, rootKey, "Intermediate CA Level 1")
	if err != nil {
		return nil, nil, err
	}
	intermediateL2Key, intermediateL2Cert, err := buildIntermediateCert(intermediateL1Cert, intermediateL1Key, "Intermediate CA Level 2")
	if err != nil {
		return nil, nil, err
	}
	if subjectSerialNumber == "" {
		subjectSerialNumber = "32121323"
	}
	signingKey, signingCert, err := BuildSigningCert(identifiers, intermediateL2Cert, intermediateL2Key, subjectSerialNumber)
	if err != nil {
		return nil, nil, err
	}
	return []*x509.Certificate{
			signingCert,
			intermediateL2Cert,
			intermediateL1Cert,
			rootCert,
		}, []*rsa.PrivateKey{
			signingKey,
			intermediateL2Key,
			intermediateL1Key,
			rootKey,
		}, nil
}

func BuildSigningCert(identifiers []string, intermediateL2Cert *x509.Certificate, intermediateL2Key *rsa.PrivateKey, serialNumber string) (*rsa.PrivateKey, *x509.Certificate, error) {
	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	signingTmpl, err := signingCertTemplate(nil, identifiers)
	if err != nil {
		return nil, nil, err
	}
	signingTmpl.Subject.SerialNumber = serialNumber
	signingCert, err := createCert(signingTmpl, intermediateL2Cert, &signingKey.PublicKey, intermediateL2Key)
	if err != nil {
		return nil, nil, err
	}
	return signingKey, signingCert, err
}

func buildIntermediateCert(parentCert *x509.Certificate, parentKey *rsa.PrivateKey, subjectName string) (*rsa.PrivateKey, *x509.Certificate, error) {
	intermediateL1Key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	intermediateL1Tmpl, err := certTemplate(subjectName)
	if err != nil {
		return nil, nil, err
	}
	intermediateL1Cert, err := createCert(intermediateL1Tmpl, parentCert, &intermediateL1Key.PublicKey, parentKey)
	if err != nil {
		return nil, nil, err
	}
	return intermediateL1Key, intermediateL1Cert, nil
}

func BuildRootCert() (*rsa.PrivateKey, *x509.Certificate, error) {
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	rootCertTmpl, err := certTemplate("Root CA")
	if err != nil {
		return nil, nil, err
	}
	rootCert, err := createCert(rootCertTmpl, rootCertTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, nil, err
	}
	return rootKey, rootCert, nil
}

// certTemplate generates a template for a x509 certificate with a given serial number. If no serial number is provided, a random one is generated.
// The certificate is valid for one month and uses SHA256 with RSA for the signature algorithm.
func certTemplate(subjectName string) (*x509.Certificate, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 8)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)
	tmpl := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{Organization: []string{subjectName}},
		SignatureAlgorithm:    x509.SHA256WithRSA,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 30), // valid for a month
		BasicConstraintsValid: true,
	}
	tmpl.IsCA = true
	tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	return &tmpl, nil
}

// createCert generates a new x509 certificate using the provided template and parent certificates, public and private keys.
// It returns the generated certificate, its PEM-encoded version, and any error encountered during the process.
func createCert(template, parent *x509.Certificate, pub interface{}, parentPriv interface{}) (cert *x509.Certificate, err error) {
	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, pub, parentPriv)
	if err != nil {
		return nil, err
	}
	// parse the resulting certificate so we can use it again
	cert, err = x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}
	return cert, err
}

// signingCertTemplate creates a x509.Certificate template for a signing certificate with an optional serial number.
func signingCertTemplate(serialNumber *big.Int, identifiers []string) (*x509.Certificate, error) {
	// generate a random serial number (a real cert authority would have some logic behind this)
	if serialNumber == nil {
		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 8)
		serialNumber, _ = rand.Int(rand.Reader, serialNumberLimit)
	}

	tmpl := x509.Certificate{
		SignatureAlgorithm: x509.SHA256WithRSA,
		SerialNumber:       serialNumber,
		Subject: pkix.Name{
			Organization:       []string{"NUTS Foundation"},
			CommonName:         "www.example.com",
			Country:            []string{"NL"},
			Locality:           []string{"Amsterdam", "The Hague"},
			OrganizationalUnit: []string{"The A-Team"},
			StreetAddress:      []string{"Amsterdamseweg 100"},
			PostalCode:         []string{"1011 NL"},
			Province:           []string{"Noord-Holland"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 30), // valid for a month
	}
	tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	// Either the ExtraExtensions SubjectAlternativeNameType is set, or the Subject Alternate Name values are set,
	// both don't mix
	if len(identifiers) > 0 {
		err := addCertSan(&tmpl, identifiers, "testhost.example.com")
		if err != nil {
			return nil, err
		}
	} else {
		tmpl.DNSNames = []string{"www.example.com", "example.com"}
		tmpl.EmailAddresses = []string{"info@example.com", "no-reply@example.org"}
		tmpl.IPAddresses = []net.IP{net.ParseIP("192.1.2.3"), net.ParseIP("192.1.2.4")}
	}
	return &tmpl, nil
}

func addCertSan(tmpl *x509.Certificate, identifiers []string, altHostName string) error {
	// OtherName represents a structure for other name in ASN.1
	type OtherName struct {
		TypeID asn1.ObjectIdentifier
		Value  asn1.RawValue `asn1:"tag:0,explicit"`
	}
	var (
		// SubjectAlternativeNameType defines the OID for Subject Alternative Name
		SubjectAlternativeNameType = asn1.ObjectIdentifier{2, 5, 29, 17}
		// OtherNameType defines the OID for Other Name
		OtherNameType = asn1.ObjectIdentifier{2, 5, 5, 5}
	)

	var list []asn1.RawValue
	// Add the alternative host name first
	value, err := toRawValue(altHostName, "tag:2")
	if err != nil {
		return err
	}
	list = append(list, *value)

	for _, identifier := range identifiers {
		raw, err := toRawValue(identifier, "ia5")
		if err != nil {
			return err
		}
		otherName := OtherName{
			TypeID: OtherNameType,
			Value: asn1.RawValue{
				Class:      2,
				Tag:        0,
				IsCompound: true,
				Bytes:      raw.FullBytes,
			},
		}

		raw, err = toRawValue(otherName, "tag:0")
		if err != nil {
			return err
		}
		list = append(list, *raw)
	}
	marshal, err := asn1.Marshal(list)
	if err != nil {
		return err
	}
	tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{
		Id:       SubjectAlternativeNameType,
		Critical: false,
		Value:    marshal,
	})
	return nil
}

// toRawValue marshals an ASN.1 identifier with a given tag, then unmarshals it into a RawValue structure.
func toRawValue(value any, tag string) (*asn1.RawValue, error) {
	b, err := asn1.MarshalWithParams(value, tag)
	if err != nil {
		return nil, err
	}
	var val asn1.RawValue
	_, err = asn1.Unmarshal(b, &val)
	if err != nil {
		return nil, err
	}
	return &val, nil
}
