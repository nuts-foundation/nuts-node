package didx509

import (
	"crypto/x509"
	"errors"
	"fmt"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/pki"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"net/url"
	"slices"
	"strings"
)

const (
	MethodName                   = "x509"
	X509CertChainHeader          = "x5c"
	X509CertThumbprintHeader     = "x5t"
	X509CertThumbprintS256Header = "x5t#S256"
)

type PolicyName string

const (
	PolicyNameSubject PolicyName = "subject"
	PolicyNameSan     PolicyName = "san"
)

type SubjectPolicy string

const (
	SubjectPolicySerialNumber       SubjectPolicy = "serialNumber"
	SubjectPolicyCommonName         SubjectPolicy = "CN"
	SubjectPolicyLocality           SubjectPolicy = "L"
	SubjectPolicyCountry            SubjectPolicy = "C"
	SubjectPolicyOrganization       SubjectPolicy = "O"
	SubjectPolicyOrganizationalUnit SubjectPolicy = "OU"
)

type SanPolicy string

const (
	SanPolicyOtherName SanPolicy = "otherName"
	SanPolicyDNS       SanPolicy = "dns"
	SanPolicyEmail     SanPolicy = "email"
	SanPolicyIPAddress SanPolicy = "ip"
)

var (
	ErrDidMalformed         = errors.New("did:x509 is malformed")
	ErrDidVersion           = errors.New("did:x509 does not have version 0")
	ErrDidSanMalformed      = errors.New("did:x509 san policy is malformed")
	ErrDidSubjectMalformed  = errors.New("did:x509 subject policy is malformed")
	ErrUnkPolicyType        = errors.New("unknown policy type")
	ErrUnkSubjectPolicyType = errors.New("unknown subject policy type")
	ErrUnkSANPolicyType     = errors.New("unknown subject SAN type")
	ErrX509ChainMissing     = errors.New("x509 rootCert chain is missing")
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
	Method      HashAlgorithm
	RootCertRef string
	PolicyName  PolicyName
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
				return nil, errors.New("x5t#S256 header does not match the certificate from the x5t headers")
			}
		}
	}
	return validationCert, nil
}

// validatePolicy validates a certificate against a given X509DidReference and its policy.
func validatePolicy(ref *X509DidReference, cert *x509.Certificate) error {

	switch ref.PolicyName {
	case PolicyNameSubject:
		keyValue := strings.Split(ref.PolicyValue, ":")
		if len(keyValue)%2 != 0 {
			return ErrDidSubjectMalformed
		}
		for i := 0; i < len(keyValue); i = i + 2 {
			subject := cert.Subject
			key := SubjectPolicy(keyValue[i])
			value, err := url.QueryUnescape(keyValue[i+1])
			if err != nil {
				return err
			}
			switch key {
			case SubjectPolicySerialNumber:
				if subject.SerialNumber != value {
					return fmt.Errorf("query does not match the subject : %s", key)
				}
			case SubjectPolicyCommonName:
				if subject.CommonName != value {
					return fmt.Errorf("query does not match the subject : %s", key)
				}
			case SubjectPolicyLocality:
				if !slices.Contains(subject.Locality, value) {
					return fmt.Errorf("query does not match the subject : %s", key)
				}
			case SubjectPolicyCountry:
				if !slices.Contains(subject.Country, value) {
					return fmt.Errorf("query does not match the subject : %s", key)
				}
			case SubjectPolicyOrganization:
				if !slices.Contains(subject.Organization, value) {
					return fmt.Errorf("query does not match the subject : %s", key)
				}
			case SubjectPolicyOrganizationalUnit:
				if !slices.Contains(subject.OrganizationalUnit, value) {
					return fmt.Errorf("query does not match the subject : %s", key)
				}
			default:
				return ErrUnkSubjectPolicyType
			}
		}
	case PolicyNameSan:
		keyValue := strings.Split(ref.PolicyValue, ":")
		if len(keyValue)%2 != 0 {
			return ErrDidSanMalformed
		}
		for i := 0; i < len(keyValue); i = i + 2 {
			key := SanPolicy(keyValue[i])
			value, err := url.QueryUnescape(keyValue[i+1])
			if err != nil {
				return err
			}
			switch key {
			case SanPolicyOtherName:
				nameValue, err := findOtherNameValue(cert)
				if err != nil {
					return err
				}
				if nameValue != value {
					return fmt.Errorf("the SAN attribute %s does not match the query", key)
				}
			case SanPolicyDNS:
				if !slices.Contains(cert.DNSNames, value) {
					return fmt.Errorf("the SAN attribute %s does not match the query", key)
				}
			case SanPolicyEmail:
				if !slices.Contains(cert.EmailAddresses, value) {
					return fmt.Errorf("the SAN attribute %s does not match the query", key)
				}
			case SanPolicyIPAddress:
				ok := false
				for _, ip := range cert.IPAddresses {
					if ip.String() == value {
						ok = true
						break
					}
				}
				if !ok {
					return fmt.Errorf("the SAN attribute %s does not match the query", key)
				}

			default:
				return ErrUnkSANPolicyType
			}
		}
	default:
		return ErrUnkPolicyType
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
	ref.Method = HashAlgorithm(didParts[1])
	ref.RootCertRef = didParts[2]
	policyFragments := strings.Split(policyString, ":")
	if len(policyFragments) > 1 {
		ref.PolicyName = PolicyName(policyFragments[0])
		ref.PolicyValue = strings.Join(policyFragments[1:], ":")
	}

	return &ref, nil
}
