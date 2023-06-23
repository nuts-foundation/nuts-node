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

//go:embed certificate-and-key.pem
var CertificateData []byte

//go:embed invalid-cert.pem
var InvalidCertificateData []byte

//go:embed truststore.pem
var TruststoreData []byte

func CertificateFile(t *testing.T) string {
	return writeToTemp(t, "certificate.pem", CertificateData)
}

func InvalidCertificate() tls.Certificate {
	cert, err := tls.X509KeyPair(CertificateData, CertificateData)
	if err != nil {
		panic(err)
	}
	cert.Leaf, _ = x509.ParseCertificate(cert.Certificate[0])
	return cert
}

func Certificate() tls.Certificate {
	cert, err := tls.X509KeyPair(CertificateData, CertificateData)
	if err != nil {
		panic(err)
	}
	cert.Leaf, _ = x509.ParseCertificate(cert.Certificate[0])
	return cert
}

func InvalidCertificateFile(t *testing.T) string {
	return writeToTemp(t, "invalid-cert.pem", InvalidCertificateData)
}

func TruststoreFile(t *testing.T) string {
	return writeToTemp(t, "truststore.pem", TruststoreData)
}

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
