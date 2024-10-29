package didx509

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"github.com/lestrrat-go/jwx/v2/cert"
	"math/big"
	"net"
	"time"
)

// BuildCertChain generates a certificate chain, including root, intermediate, and signing certificates.
func BuildCertChain(identifier string) (chainCerts *[4]x509.Certificate, chain *cert.Chain, rootCertificate *x509.Certificate, signingKey *rsa.PrivateKey, signingCert *x509.Certificate, err error) {
	chainCerts = &[4]x509.Certificate{}
	chain = &cert.Chain{}
	rootKey, rootCert, rootPem, err := buildRootCert(err)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	chainCerts[0] = *rootCert
	err = chain.Add(rootPem)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	intermediateL1Key, intermediateL1Cert, intermediateL1Pem, err := buildIntermediateCert(err, rootCert, rootKey)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	chainCerts[1] = *intermediateL1Cert
	err = chain.Add(intermediateL1Pem)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	intermediateL2Key, intermediateL2Cert, intermediateL2Pem, err := buildIntermediateCert(err, intermediateL1Cert, intermediateL1Key)
	chainCerts[2] = *intermediateL2Cert
	err = chain.Add(intermediateL2Pem)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	signingKey, signingCert, signingPEM, err := buildSigningCert(identifier, intermediateL2Cert, intermediateL2Key, "32121323")
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	chainCerts[3] = *signingCert
	err = chain.Add(signingPEM)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	return chainCerts, chain, rootCert, signingKey, signingCert, nil
}

func buildSigningCert(identifier string, intermediateL2Cert *x509.Certificate, intermediateL2Key *rsa.PrivateKey, serialNumber string) (*rsa.PrivateKey, *x509.Certificate, []byte, error) {
	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, err
	}
	signingTmpl, err := SigningCertTemplate(nil, identifier)
	if err != nil {
		return nil, nil, nil, err
	}
	signingTmpl.Subject.SerialNumber = serialNumber
	signingCert, signingPEM, err := CreateCert(signingTmpl, intermediateL2Cert, &signingKey.PublicKey, intermediateL2Key)
	if err != nil {
		return nil, nil, nil, err
	}
	return signingKey, signingCert, signingPEM, err
}

func buildIntermediateCert(err error, parentCert *x509.Certificate, parentKey *rsa.PrivateKey) (*rsa.PrivateKey, *x509.Certificate, []byte, error) {
	intermediateL1Key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, err
	}
	intermediateL1Tmpl, err := CertTemplate(nil)
	if err != nil {
		return nil, nil, nil, err
	}
	intermediateL1Cert, intermediateL1Pem, err := CreateCert(intermediateL1Tmpl, parentCert, &intermediateL1Key.PublicKey, parentKey)
	if err != nil {
		return nil, nil, nil, err
	}
	return intermediateL1Key, intermediateL1Cert, intermediateL1Pem, nil
}

func buildRootCert(err error) (*rsa.PrivateKey, *x509.Certificate, []byte, error) {
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, err
	}
	rootCertTmpl, err := CertTemplate(nil)
	if err != nil {
		return nil, nil, nil, err
	}
	rootCert, rootPem, err := CreateCert(rootCertTmpl, rootCertTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, nil, nil, err
	}
	return rootKey, rootCert, rootPem, nil
}

// CertTemplate generates a template for a x509 certificate with a given serial number. If no serial number is provided, a random one is generated.
// The certificate is valid for one month and uses SHA256 with RSA for the signature algorithm.
func CertTemplate(serialNumber *big.Int) (*x509.Certificate, error) {
	// generate a random serial number (a real cert authority would have some logic behind this)
	if serialNumber == nil {
		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 8)
		serialNumber, _ = rand.Int(rand.Reader, serialNumberLimit)
	}
	tmpl := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{Organization: []string{"JaegerTracing"}},
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

// SigningCertTemplate creates a x509.Certificate template for a signing certificate with an optional serial number.
func SigningCertTemplate(serialNumber *big.Int, identifier string) (*x509.Certificate, error) {
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
	if identifier != "" {
		err := setSanAlternativeName(&tmpl, identifier)
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

func setSanAlternativeName(tmpl *x509.Certificate, identifier string) error {
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
	var list []asn1.RawValue
	list = append(list, *raw)
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
func toRawValue(identifier any, tag string) (*asn1.RawValue, error) {
	b, err := asn1.MarshalWithParams(identifier, tag)
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

// CreateCert generates a new x509 certificate using the provided template and parent certificates, public and private keys.
// It returns the generated certificate, its PEM-encoded version, and any error encountered during the process.
func CreateCert(template, parent *x509.Certificate, pub interface{}, parentPriv interface{}) (cert *x509.Certificate, certPEM []byte, err error) {

	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, pub, parentPriv)
	if err != nil {
		return nil, nil, err
	}
	// parse the resulting certificate so we can use it again
	cert, err = x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, err
	}
	// PEM encode the certificate (this is a standard TLS encoding)
	b := pem.Block{Type: "CERTIFICATE", Bytes: certDER}
	certPEM = pem.EncodeToMemory(&b)
	return cert, certPEM, err
}
