package didx509

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/lestrrat-go/jwx/v2/cert"
	"golang.org/x/crypto/sha3"
)

type HashAlgorithm string

const (
	HashSha1   = HashAlgorithm("sha1")
	HashSha256 = HashAlgorithm("sha256")
	HashSha384 = HashAlgorithm("sha384")
	HashSha512 = HashAlgorithm("sha512")
)

// OtherName represents a structure for other name in ASN.1
type OtherName struct {
	TypeID asn1.ObjectIdentifier
	Value  asn1.RawValue `asn1:"tag:0,explicit"`
}

// SanType is an alias for pkix.AttributeTypeAndValue
type SanType pkix.AttributeTypeAndValue

// SanTypeName represents the type name for SAN
type SanTypeName string

var (
	// SubjectAlternativeNameType defines the OID for Subject Alternative Name
	SubjectAlternativeNameType = asn1.ObjectIdentifier{2, 5, 29, 17}
	// OtherNameType defines the OID for Other Name
	OtherNameType = asn1.ObjectIdentifier{2, 5, 5, 5}
)

// findOtherNameValue extracts the value of a specified OtherName type from the certificate
func findOtherNameValue(cert *x509.Certificate) (string, error) {
	value := ""
	for _, extension := range cert.Extensions {
		if extension.Id.Equal(SubjectAlternativeNameType) {
			err := forEachSan(extension.Value, func(tag int, data []byte) error {
				if tag != 0 {
					return nil
				}
				var other OtherName
				_, err := asn1.UnmarshalWithParams(data, &other, "tag:0")
				if err != nil {
					return fmt.Errorf("could not parse requested other SAN: %v", err)
				}
				if other.TypeID.Equal(OtherNameType) {
					_, err = asn1.Unmarshal(other.Value.Bytes, &value)
					if err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return "", err
			}
			return value, err
		}
	}
	return "", nil
}

// forEachSan processes each SAN extension in the certificate
func forEachSan(extension []byte, callback func(tag int, data []byte) error) error {
	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(extension, &seq)
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return fmt.Errorf("x509: trailing data after X.509 extension")
	}

	if !isSANSequence(seq) {
		return asn1.StructuralError{Msg: "bad SAN sequence"}
	}

	return processSANSequence(seq.Bytes, callback)
}

// isSANSequence checks if the provided ASN.1 value is a SAN sequence
func isSANSequence(seq asn1.RawValue) bool {
	return seq.IsCompound && seq.Tag == 16 && seq.Class == 0
}

// processSANSequence processes the SAN sequence and invokes the callback on each element
func processSANSequence(rest []byte, callback func(tag int, data []byte) error) error {
	for len(rest) > 0 {
		var v asn1.RawValue
		var err error

		rest, err = asn1.Unmarshal(rest, &v)
		if err != nil {
			return err
		}

		if err := callback(v.Tag, v.FullBytes); err != nil {
			return err
		}
	}
	return nil
}

// parseChain extracts the certificate chain from the provided metadata
func parseChain(headerChain *cert.Chain) ([]*x509.Certificate, error) {
	chain := make([]*x509.Certificate, headerChain.Len())
	for i := range headerChain.Len() {
		certBytes, has := headerChain.Get(i)
		if has {
			pemBlock, _ := pem.Decode(certBytes)
			if pemBlock == nil {
				return nil, fmt.Errorf("invalid PEM block")
			}
			if pemBlock.Type != "CERTIFICATE" {
				return nil, fmt.Errorf("invalid PEM block type: %s", pemBlock.Type)
			}
			certificate, err := x509.ParseCertificate(pemBlock.Bytes)
			if err != nil {
				return nil, err
			}
			chain[i] = certificate
		}
	}
	return chain, nil
}

// findCertificateByHash searches for a certificate in the provided chain using the given base64url-encoded hash and algorithm.
// If a matching certificate is found, it returns the certificate; otherwise, it returns an error.
func findCertificateByHash(chain []*x509.Certificate, targetHashString string, alg HashAlgorithm) (*x509.Certificate, error) {
	targetHash, err := base64.RawURLEncoding.DecodeString(targetHashString)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64url hash: %v", err)
	}

	for _, c := range chain {
		certHash, err := hash(c.Raw, alg)
		if err != nil {
			return nil, err
		}
		if bytes.Equal(targetHash, certHash) {
			return c, nil
		}
	}

	return nil, fmt.Errorf("cannot find a certificate with alg: %s hash: %s", alg, targetHashString)
}

// hash computes and returns the hash of the given data using the specified algorithm.
// Supported algorithms are: "sha1", "sha256", "sha384", "sha512".
// Returns the computed hash as a byte slice and an error if the algorithm is unsupported.
// The error is nil if the hash is computed successfully.
func hash(data []byte, alg HashAlgorithm) ([]byte, error) {
	switch alg {
	case HashSha1:
		sum := sha1.Sum(data)
		return sum[:], nil
	case HashSha256:
		sum := sha256.Sum256(data)
		return sum[:], nil
	case HashSha384:
		sum := sha3.Sum384(data)
		return sum[:], nil
	case HashSha512:
		sum := sha512.Sum512(data)
		return sum[:], nil
	}
	return nil, fmt.Errorf("unsupported hash algorithm: %s", alg)
}
