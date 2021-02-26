package x509

import (
	"crypto"
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

func createCrl(currentCrl *x509.RevocationList, issuer *x509.Certificate, priv crypto.Signer, certsToRevoke []*x509.Certificate) ([]byte, error) {
	if currentCrl == nil {
		randSerial, _ := rand.Int(rand.Reader, big.NewInt(big.MaxExp))
		currentCrl = &x509.RevocationList{Number: randSerial}
	}

	revokedCerts := currentCrl.RevokedCertificates
	for _, cert := range certsToRevoke {
		revokedCert := pkix.RevokedCertificate{
			SerialNumber:   cert.SerialNumber,
			RevocationTime: time.Now(),
		}
		revokedCerts = append(revokedCerts, revokedCert)
	}

	template := &x509.RevocationList{
		//SignatureAlgorithm:  x509.SHA256WithRSA,
		RevokedCertificates: revokedCerts,
		Number:              big.NewInt(0).Add(currentCrl.Number, big.NewInt(1)),
		ThisUpdate:          time.Now(),
		NextUpdate:          time.Now().Add(24 * time.Hour),
	}
	return x509.CreateRevocationList(rand.Reader, template, issuer, priv)
}
