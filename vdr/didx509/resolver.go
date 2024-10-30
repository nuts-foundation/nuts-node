package didx509

import (
	"crypto/x509"
	"errors"
	"fmt"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/pki"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"strings"
)

const (
	MethodName                   = "x509"
	X509CertChainHeader          = "x5c"
	X509CertThumbprintHeader     = "x5t"
	X509CertThumbprintS256Header = "x5t#S256"
)

var (
	ErrX509ChainMissing            = errors.New("x509 rootCert chain is missing")
	ErrNoCertsInHeaders            = errors.New("no x5t or x5t#S256 header found")
	ErrNoMatchingHeaderCredentials = errors.New("x5t#S256 header does not match the certificate from the x5t headers")
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

type X509DidPolicy struct {
	Name  PolicyName
	Value string
}

type X509DidReference struct {
	Method      HashAlgorithm
	RootCertRef string
	Policies    []X509DidPolicy
}

// Resolve resolves a DID document given its identifier and corresponding metadata.
func (r Resolver) Resolve(id did.DID, metadata *resolver.ResolveMetadata) (*did.Document, *resolver.DocumentMetadata, error) {
	if id.Method != MethodName {
		return nil, nil, fmt.Errorf("unsupported DID method: %s", id.Method)
	}
	ref, err := parseX509Did(id)
	if err != nil {
		return nil, nil, err
	}

	chainHeader, ok := metadata.GetProtectedHeaderChain(X509CertChainHeader)
	if !ok {
		return nil, nil, ErrX509ChainMissing
	}
	chain, err := parseChain(chainHeader)
	if err != nil {
		return nil, nil, err
	}
	_, err = findCertificateByHash(chain, ref.RootCertRef, ref.Method)
	if err != nil {
		return nil, nil, err
	}
	validationCert, err := findValidationCertificate(metadata, chain)
	if err != nil {
		return nil, nil, err
	}

	err = ValidatePolicy(ref, validationCert)
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

// findValidationCertificate retrieves the validation certificate from the given chain based on metadata-provided thumbprints.
func findValidationCertificate(metadata *resolver.ResolveMetadata, chain []*x509.Certificate) (*x509.Certificate, error) {
	var validationCert *x509.Certificate
	var err error
	hashHeader, found := metadata.GetProtectedHeaderString(X509CertThumbprintHeader)
	if found {
		validationCert, err = findCertificateByHash(chain, hashHeader, HashSha1)
		if err != nil {
			return nil, err
		}
	}
	hash256Header, found := metadata.GetProtectedHeaderString(X509CertThumbprintS256Header)
	if found {
		otherValidationCert, err := findCertificateByHash(chain, hash256Header, HashSha256)
		if err != nil {
			return nil, err
		}
		if validationCert == nil {
			validationCert = otherValidationCert
		} else {
			if !otherValidationCert.Equal(validationCert) {
				return nil, ErrNoMatchingHeaderCredentials
			}
		}
	}
	if validationCert == nil {
		return nil, ErrNoCertsInHeaders
	}
	return validationCert, nil
}

// createDidDocument generates a new DID Document based on the provided DID identifier and validation certificate.
func createDidDocument(id did.DID, validationCert *x509.Certificate) (*did.Document, error) {
	didUrl := did.DIDURL{DID: id, Fragment: "0"}
	verificationMethod, err := did.NewVerificationMethod(didUrl, ssi.JsonWebKey2020, id, validationCert.PublicKey)
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
	document.AddKeyAgreement(verificationMethod)
	document.AddAssertionMethod(verificationMethod)
	document.AddAuthenticationMethod(verificationMethod)
	document.AddCapabilityDelegation(verificationMethod)
	document.AddCapabilityInvocation(verificationMethod)
	return document, nil
}

// parseX509Did parses a DID (Decentralized Identifier) in the x509 format and returns a corresponding X509DidReference.
func parseX509Did(id did.DID) (*X509DidReference, error) {
	ref := X509DidReference{}
	fullDidString := id.ID
	policyStrings := []string{}
	didString := ""
	fullDidParts := strings.Split(fullDidString, "::")
	if len(fullDidParts) == 1 {
		didString = fullDidParts[0]
	} else if len(fullDidParts) > 1 {
		didString = fullDidParts[0]
		policyStrings = fullDidParts[1:]
	}
	didParts := strings.Split(didString, ":")
	if len(didParts) != 3 {
		return nil, ErrDidMalformed
	}

	if didParts[0] != "0" {
		return nil, ErrDidVersion
	}
	ref.Method = HashAlgorithm(didParts[1])
	ref.RootCertRef = didParts[2]

	for _, policyString := range policyStrings {
		policyFragments := strings.Split(policyString, ":")
		if len(policyFragments) > 1 {
			policy := X509DidPolicy{Name: PolicyName(policyFragments[0]), Value: strings.Join(policyFragments[1:], ":")}
			ref.Policies = append(ref.Policies, policy)
		} else {
			return nil, ErrDidPolicyMalformed
		}
	}
	return &ref, nil
}
