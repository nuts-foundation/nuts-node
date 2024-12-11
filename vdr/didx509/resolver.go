/*
 * Copyright (C) 2024 Nuts community
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

package didx509

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/pki"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"strings"
)

const (

	// MethodName represents the x509 DID method identifier.
	MethodName = "x509"

	// X509CertChainHeader represents the header key for the x509 certificate chain in a JWT.
	X509CertChainHeader = "x5c"

	// X509CertThumbprintHeader represents the header for the thumbprint of an x509 certificate using SHA-1.
	X509CertThumbprintHeader = "x5t"

	// X509CertThumbprintS256Header represents a header for the X.509 certificate thumbprint using the SHA-256 hashing algorithm.
	X509CertThumbprintS256Header = "x5t#S256"
)

var (

	// ErrX509ChainMissing indicates that no x5c header was found in the provided metadata.
	ErrX509ChainMissing = errors.New("no x5c header found")

	// ErrNoCertsInHeaders indicates that no x5t or x5t#S256 header was found in the provided metadata.
	ErrNoCertsInHeaders = errors.New("no x5t or x5t#S256 header found")

	// ErrNoMatchingHeaderCredentials indicates that the x5t#S256 header does not match the certificate from the x5t headers.
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

// X509DidPolicy represents an X.509 DID policy that includes a policy name and corresponding value.
type X509DidPolicy struct {
	Name  PolicyName
	Value string
}

// X509DidReference represents a reference for an X.509 Decentralized Identifier (DID).
type X509DidReference struct {
	// Method specifies the hash algorithm that was used to generate CAFingerprint from the raw DER bytes of the CA certificate.
	Method HashAlgorithm
	// CAFingerprint is the fingerprint of the CA certificate.
	CAFingerprint string
	// Policies contain the fields that are included in the did:x509, which must be validated against the certificates.
	Policies []X509DidPolicy
}

// Resolve resolves a DID document given its identifier and corresponding metadata.
// The resolve method resolves using the did:x509 v1.0 Draft method specification found at:
// https://trustoverip.github.io/tswg-did-x509-method-specification/
// Given this specification, this implementation diverges from the spec at the following:
// * Besides the "san" policies "email" / "dns" / "uri", the san policy "otherName" is also implemented.
// * The policy "subject" also supports "serialNumber", besides the "CN" / "L" / "ST" / "O" / "OU" / "C" / "STREET" fields.
// * The policy "eku" is not implemented.
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
		return nil, nil, fmt.Errorf("did:x509 x5c certificate parsing: %w", err)
	}
	caFingerprintCert, err := findCertificateByHash(chain, ref.CAFingerprint, ref.Method)
	if err != nil {
		return nil, nil, err
	}
	validationCert, err := findValidationCertificate(metadata, chain)
	if err != nil {
		return nil, nil, err
	}
	if bytes.Equal(caFingerprintCert.Raw, validationCert.Raw) {
		return nil, nil, fmt.Errorf("did:x509 ca-fingerprint refers to leaf certificate, must be either root or intermediate CA certificate")
	}

	// Validate certificate chain, checking signatures and whether the chain is complete
	var chainWithoutLeaf []*x509.Certificate
	for _, curr := range chain {
		if curr.Equal(validationCert) {
			continue
		}
		chainWithoutLeaf = append(chainWithoutLeaf, curr)
	}
	trustStore := core.BuildTrustStore(chainWithoutLeaf)
	verifiedChains, err := validationCert.Verify(x509.VerifyOptions{
		Intermediates: core.NewCertPool(trustStore.IntermediateCAs),
		Roots:         core.NewCertPool(trustStore.RootCAs),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("did:509 certificate chain validation failed: %w", err)
	}

	err = validatePolicy(ref, validationCert)
	if err != nil {
		return nil, nil, err
	}

	// Check CRLs on the verifiedChain, but
	// 		only after the integrity of the chain has been verified, and
	// 		only after we have established it is appropriate to use this chain.
	// Any CAs/CRLs in the verifiedChain will from hereon exist in the CRL checker and will be periodically updated
	err = r.pkiValidator.CheckCRLStrict(verifiedChains[0])
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
	ref.CAFingerprint = didParts[2]

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
