package didx509

import (
	"crypto/x509"
	"errors"
	"fmt"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/pki"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
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
	ErrWrongSanOtherName       = errors.New("the SAN otherName does not match the query")
	ErrWrongSanDns             = errors.New("the SAN DNS does not match the query")
	ErrWrongSanEmailAddresses  = errors.New("the SAN EmailAddresses does not match the query")
	ErrWrongSanIPAddresses     = errors.New("the SAN IPAddresses does not match the query")
	ErrDidMalformed            = errors.New("did:x509 is malformed")
	ErrDidVersion              = errors.New("did:x509 does not have version 0")
	ErrDidSanMalformed         = errors.New("did:x509 policy is malformed")
	ErrX509ChainMissing        = errors.New("x509 rootCert chain is missing")
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

// Resolve resolves a DID document given its identifier and corresponding metadata.
func (r Resolver) Resolve(id did.DID, metadata *resolver.ResolveMetadata) (*did.Document, *resolver.DocumentMetadata, error) {
	if id.Method != MethodName {
		return nil, nil, fmt.Errorf("unsupported DID method: %s", id.Method)
	}
	ref, err := parseX509Did(id)
	if err != nil {
		return nil, nil, err
	}

	chainHeader, ok := metadata.GetProtectedHeaderChain("x5c")
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
	hashHeader, _ := metadata.GetProtectedHeaderString("x5t")
	validationCert, err := findCertificateByHash(chain, hashHeader, "sha1")
	if err != nil {
		hash256Header, _ := metadata.GetProtectedHeaderString("x5t#S256")
		validationCert, err = findCertificateByHash(chain, hash256Header, "sha256")
		if err != nil {
			return nil, nil, err
		}
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

// validatePolicy validates a certificate against a given X509DidReference and its policy.
func validatePolicy(ref *X509DidReference, cert *x509.Certificate) error {

	switch ref.PolicyName {
	case "subject":
		keyValue := strings.Split(ref.PolicyValue, ":")
		if len(keyValue)%2 != 0 {
			return ErrDidSanMalformed
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
				if !slices.Contains(subject.Locality, value) {
					return ErrWrongLocality
				}
			case "O":
				if !slices.Contains(subject.Organization, value) {
					return ErrWrongOrganization
				}
			case "OU":
				if !slices.Contains(subject.OrganizationalUnit, value) {
					return ErrWrongOrganizationalUnit
				}
			}
		}
	case "san":
		keyValue := strings.Split(ref.PolicyValue, ":")
		if len(keyValue)%2 != 0 {
			return ErrDidSanMalformed
		}
		for i := 0; i < len(keyValue); i = i + 2 {
			key := keyValue[i]
			value := keyValue[i+1]
			switch key {
			case "otherName":
				nameValue, err := findOtherNameValue(cert)
				if err != nil {
					return err
				}
				if nameValue != value {
					return ErrWrongSanOtherName
				}
			case "dns":
				if len(cert.DNSNames) > 0 && !slices.Contains(cert.DNSNames, value) {
					return ErrWrongSanDns
				}
			case "email":
				if len(cert.EmailAddresses) > 0 && !slices.Contains(cert.EmailAddresses, value) {
					return ErrWrongSanEmailAddresses
				}
			case "ip":
				if len(cert.IPAddresses) > 0 {
					ok := false
					for _, ip := range cert.IPAddresses {
						if ip.String() == value {
							ok = true
							break
						}
					}
					if !ok {
						return ErrWrongSanIPAddresses
					}

				}
			}

		}
	}

	return nil
}

// createDidDocument generates a new DID Document based on the provided DID identifier and validation certificate.
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
	document.AddCapabilityDelegation(verificationMethod)
	document.AddCapabilityInvocation(verificationMethod)
	document.AddKeyAgreement(verificationMethod)
	return document, nil
}

// parseX509Did parses a DID (Decentralized Identifier) in the x509 format and returns a corresponding X509DidReference.
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
		return nil, ErrDidMalformed
	}

	if didParts[0] != "0" {
		return nil, ErrDidVersion
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
