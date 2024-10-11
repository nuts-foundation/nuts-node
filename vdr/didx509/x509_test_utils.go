package didx509

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"github.com/lestrrat-go/jwx/v2/cert"
	"math/big"
	"time"
)

// BuildCertChain generates a certificate chain, including root, intermediate, and signing certificates.
func BuildCertChain(identifier string) (chainCerts *[4]x509.Certificate, chain *cert.Chain, rootCertificate *x509.Certificate, signingKey *rsa.PrivateKey, signingCert *x509.Certificate, err error) {
	chainCerts = &[4]x509.Certificate{}
	chain = &cert.Chain{}
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	rootCertTmpl, err := CertTemplate(nil)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	rootCertTmpl.IsCA = true
	rootCertTmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	rootCertTmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	rootCert, rootPem, err := CreateCert(rootCertTmpl, rootCertTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	chainCerts[0] = *rootCert
	err = chain.Add(rootPem)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	intermediateL1Key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	intermediateL1Tmpl, err := CertTemplate(nil)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	intermediateL1Tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	intermediateL1Tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	intermediateL1Cert, intermediateL1Pem, err := CreateCert(intermediateL1Tmpl, rootCertTmpl, &intermediateL1Key.PublicKey, rootKey)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	chainCerts[1] = *intermediateL1Cert
	err = chain.Add(intermediateL1Pem)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	intermediateL2Key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	intermediateL2Tmpl, err := CertTemplate(nil)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	intermediateL2Tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	intermediateL2Tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	intermediateL2Cert, intermediateL2Pem, err := CreateCert(intermediateL2Tmpl, intermediateL1Cert, &intermediateL2Key.PublicKey, intermediateL1Key)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	chainCerts[2] = *intermediateL2Cert
	err = chain.Add(intermediateL2Pem)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	signingKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	signingTmpl, err := SigningCertTemplate(nil, identifier)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	signingTmpl.Subject.SerialNumber = "32121323"
	signingTmpl.KeyUsage = x509.KeyUsageDigitalSignature
	signingTmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	signingCert, signingPEM, err := CreateCert(signingTmpl, intermediateL2Cert, &signingKey.PublicKey, intermediateL2Key)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	chainCerts[3] = *signingCert
	err = chain.Add(signingPEM)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	return chainCerts, chain, rootCert, signingKey, signingCert, nil
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
	return &tmpl, nil
}

// SigningCertTemplate creates a x509.Certificate template for a signing certificate with an optional serial number.
func SigningCertTemplate(serialNumber *big.Int, identifier string) (*x509.Certificate, error) {
	// generate a random serial number (a real cert authority would have some logic behind this)
	if serialNumber == nil {
		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 8)
		serialNumber, _ = rand.Int(rand.Reader, serialNumberLimit)
	}
	raw, err := toRawValue(identifier, "ia5")
	if err != nil {
		return nil, err
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
		return nil, err
	}
	var list []asn1.RawValue
	list = append(list, *raw)
	marshal, err := asn1.Marshal(list)
	if err != nil {
		return nil, err
	}

	tmpl := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{Organization: []string{"JaegerTracing"}},
		SignatureAlgorithm:    x509.SHA256WithRSA,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 30), // valid for a month
		EmailAddresses:        []string{"roland@edia.nl"},
		BasicConstraintsValid: true,
		ExtraExtensions: []pkix.Extension{
			{
				Id:       SubjectAlternativeNameType,
				Critical: false,
				Value:    marshal,
			},
		},
	}
	return &tmpl, nil
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

// DebugUnmarshall recursively unmarshalls ASN.1 encoded data and prints the structure with parsed values.
func DebugUnmarshall(data []byte, depth int) error {
	for len(data) > 0 {
		var x asn1.RawValue
		tail, err := asn1.Unmarshal(data, &x)
		if err != nil {
			return err
		}
		prefix := ""
		for i := 0; i < depth; i++ {
			prefix += "\t"
		}
		fmt.Printf("%sUnmarshalled: compound: %t, tag: %d, class: %d", prefix, x.IsCompound, x.Tag, x.Class)

		if x.Bytes != nil {
			if x.IsCompound || x.Tag == 0 {
				fmt.Println()
				err := DebugUnmarshall(x.Bytes, depth+1)
				if err != nil {
					return err
				}
			} else {
				switch x.Tag {
				case asn1.TagBoolean:
					fmt.Printf(", value boolean: %v", x.Bytes)
				case asn1.TagOID:
					fmt.Printf(", value: OID: %v", x.Bytes)
				case asn1.TagInteger:
					fmt.Printf(", value: integer: %v", x.Bytes)
				case asn1.TagUTF8String:
					fmt.Printf(", value: bitstring: %v", x.Bytes)
				case asn1.TagBitString:
					fmt.Printf(", value: bitstring: %v", x.Bytes)
				case asn1.TagOctetString:
					fmt.Printf(", value: octetstring: %v", x.Bytes)
				case asn1.TagIA5String:
					fmt.Printf(", value: TagIA5String: %v", x.Bytes)
				case asn1.TagNull:
					fmt.Printf(", value: null")
				default:
					return fmt.Errorf("unknown tag: %d", x.Tag)

				}
				fmt.Println()
			}
		}
		data = tail
	}

	return nil
}
