package didx509

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/pki"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"golang.org/x/crypto/sha3"
	"slices"
	"strings"
)

const MethodName = "x509"

var (
	ErrWrongSerialNumber       = errors.New("query does not match the subject serialNumber")
	ErrWrongCN                 = errors.New("query does not match the subject CN")
	ErrWrongLocality           = errors.New("query does not match the subject Locality")
	ErrWrongOrganization       = errors.New("query does not match the subject Organization")
	ErrWrongOrganizationalUnit = errors.New("query does not match the subject OrganizationalUnit")
)

var _ resolver.DIDResolver = &Resolver{}

// NewResolver creates a new Resolver.
func NewResolver(pkiValidator pki.Validator) *Resolver {
	return &Resolver{
		pkiValidator: pkiValidator,
	}
}

type Resolver struct {
	pkiValidator pki.Validator
}

type X509DidReference struct {
	Method      string
	RootCertRef string
	PolicyName  string
	PolicyValue string
}

func (r Resolver) Resolve(id did.DID, metadata *resolver.ResolveMetadata) (*did.Document, *resolver.DocumentMetadata, error) {
	if id.Method != MethodName {
		return nil, nil, fmt.Errorf("unsupported DID method: %s", id.Method)
	}
	ref, err := parseX509Did(id)
	if err != nil {
		return nil, nil, err
	}

	if metadata.X509CertChain == nil {
		return nil, nil, errors.New("x509 rootCert chain is nil")
	}
	chain, err := parseChain(metadata)
	if err != nil {
		return nil, nil, err
	}
	_, err = FindCertificateByHash(chain, ref.RootCertRef, ref.Method)
	if err != nil {
		err := fmt.Errorf("unable to find root cert: %s in chain: %v", ref.RootCertRef, err)
		return nil, nil, err
	}
	validationCert, err := FindCertificateByHash(chain, metadata.X509CertThumbprint, "sha1")
	if err != nil {
		return nil, nil, err
	}

	err = validatePolicy(ref, validationCert)
	if err != nil {
		return nil, nil, err
	}

	err = r.pkiValidator.Validate(chain)
	if err != nil {
		return nil, nil, err
	}
	document, err := createDidDocument(id, validationCert)
	if err != nil {
		return nil, nil, err
	}
	return document, &resolver.DocumentMetadata{}, err
}

func validatePolicy(ref *X509DidReference, cert *x509.Certificate) error {

	switch ref.PolicyName {
	case "subject":
		keyValue := strings.Split(ref.PolicyValue, ":")
		if len(keyValue)%2 != 0 {
			return errors.New("subject selector does not have 2 parts")
		}
		for i := 0; i < len(keyValue); i = i + 2 {
			subject := cert.Subject
			key := keyValue[i]
			value := keyValue[i+1]
			switch key {
			case "serialNumber":
				if subject.SerialNumber != value {
					return ErrWrongSerialNumber
				}
			case "CN":
				if subject.CommonName != value {
					return ErrWrongCN
				}
			case "L":
				if slices.Contains(subject.Locality, value) {
					return ErrWrongLocality
				}
			case "O":
				if slices.Contains(subject.Organization, value) {
					return ErrWrongOrganization
				}
			case "OU":
				if slices.Contains(subject.OrganizationalUnit, value) {
					return ErrWrongOrganizationalUnit
				}
			}
		}

	}

	return nil
}

func createDidDocument(id did.DID, validationCert *x509.Certificate) (*did.Document, error) {
	verificationMethod, err := did.NewVerificationMethod(did.DIDURL{DID: id}, ssi.JsonWebKey2020, id, validationCert.PublicKey)
	if err != nil {
		return nil, err
	}
	document := &did.Document{
		Context: []interface{}{
			ssi.MustParseURI("https://www.w3.org/ns/did/v1"),
		},
		ID:                 id,
		Controller:         []did.DID{id},
		VerificationMethod: did.VerificationMethods{verificationMethod},
	}
	document.AddAssertionMethod(verificationMethod)
	document.AddAssertionMethod(verificationMethod)
	document.AddKeyAgreement(verificationMethod)
	return document, nil
}

func FindCertificateByHash(chain []*x509.Certificate, targetHashString, alg string) (*x509.Certificate, error) {
	targetHash, err := base64.RawURLEncoding.DecodeString(targetHashString)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64url hash: %v", err)
	}

	for _, cert := range chain {
		certHash, err := hash(cert.Raw, alg)
		if err != nil {
			return nil, err
		}
		if bytes.Equal(targetHash, certHash) {
			return cert, nil
		}
	}

	return nil, fmt.Errorf("cannot find a certificate with algorithm: %s hash: %s", alg, targetHashString)
}

func hash(data []byte, alg string) ([]byte, error) {
	switch alg {
	case "sha1":
		sum := sha1.Sum(data)
		return sum[:], nil
	case "sha256":
		sum := sha256.Sum256(data)
		return sum[:], nil
	case "sha384":
		sum := sha3.Sum384(data)
		return sum[:], nil
	case "sha512":
		sum := sha512.Sum512(data)
		return sum[:], nil
	}
	return nil, fmt.Errorf("unsupported hash algorithm: %s", alg)
}

func parseX509Did(id did.DID) (*X509DidReference, error) {
	ref := X509DidReference{}
	fullDidString := id.ID
	policyString := ""
	didString := ""
	fullDidParts := strings.Split(fullDidString, "::")
	if len(fullDidParts) == 1 {
		didString = fullDidParts[0]
	} else if len(fullDidParts) == 2 {
		didString = fullDidParts[0]
		policyString = fullDidParts[1]
	}
	didParts := strings.Split(didString, ":")
	if len(didParts) != 3 {
		return nil, errors.New("did:key does not have 3 parts")
	}

	if didParts[0] != "0" {
		return nil, errors.New("did:x509 does not have 0 as the version number")
	}
	ref.Method = didParts[1]
	ref.RootCertRef = didParts[2]
	policyFragments := strings.Split(policyString, ":")
	if len(policyFragments) > 1 {
		ref.PolicyName = policyFragments[0]
		ref.PolicyValue = strings.Join(policyFragments[1:], ":")
	}

	return &ref, nil
}

func parseChain(metadata *resolver.ResolveMetadata) ([]*x509.Certificate, error) {
	chain := make([]*x509.Certificate, metadata.X509CertChain.Len())
	for i := range metadata.X509CertChain.Len() {
		certBytes, has := metadata.X509CertChain.Get(i)
		if has {
			pemBlock, _ := pem.Decode(certBytes)
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
