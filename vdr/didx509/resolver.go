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
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"strings"
)

const (

	// MethodName represents the x509 DID method identifier.
	MethodName = "x509"

	// X509CertChainHeader represents the header key for the x509 certificate chain in a JWT.
	X509CertChainHeader = "x5c"
)

var (

	// ErrX509ChainMissing indicates that no x5c header was found in the provided metadata.
	ErrX509ChainMissing = errors.New("no x5c header found")
)

var _ resolver.DIDResolver = &Resolver{}

// NewResolver creates a new Resolver.
func NewResolver() *Resolver {
	return &Resolver{}
}

type Resolver struct {
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
// Resolve does NOT check the CRLs on the certificate chain.
func (r Resolver) Resolve(id did.DID, metadata *resolver.ResolveMetadata) (*did.Document, *resolver.DocumentMetadata, error) {
	if id.Method != MethodName {
		return nil, nil, fmt.Errorf("unsupported DID method: %s", id.Method)
	}

	// These steps align with https://trustoverip.github.io/tswg-did-x509-method-specification/#read
	// Step 1. decode x509chain
	chainHeader, ok := metadata.GetProtectedHeaderChain(X509CertChainHeader)
	if !ok {
		return nil, nil, ErrX509ChainMissing
	}
	chain, err := parseChain(chainHeader)
	if err != nil {
		return nil, nil, fmt.Errorf("did:x509 x5c certificate parsing: %w", err)
	}
	if len(chain) < 2 {
		return nil, nil, fmt.Errorf("did:x509 x5c certificate chain must contain at least two certificates")
	}
	// Step 2. build valid certificate chain
	// Step 3. check whether any certificate in the chain is revoked (using CRL, OCSP, or other mechanisms)
	//         Skipped: this check is deferred to the Verifiable Credential validation.
	//         Checking CRLs at this point would allow unsanitized user input into the CRL checker DB.
	//         CRL checking should be done where the appropriateness of usage of (i.e., trust in) the certificate chain can be confirmed.
	//         See https://github.com/nuts-foundation/nuts-node/pull/3606#issuecomment-2545051148
	validationCert := chain[0]
	trustStore := core.BuildTrustStore(chain[1:])
	validatedChains, err := validationCert.Verify(x509.VerifyOptions{
		Intermediates: core.NewCertPool(trustStore.IntermediateCAs),
		Roots:         core.NewCertPool(trustStore.RootCAs),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("did:509 certificate chain validation failed: %w", err)
	}
	validatedChain := validatedChains[0]
	if len(validatedChain) != len(chain) {
		return nil, nil, fmt.Errorf("did:x509 x5c header contains more certificates than the validated certificate chain")
	}
	// Sanity check: x5c header must be in correct order
	for i, cert := range chain {
		if !bytes.Equal(cert.Raw, validatedChain[i].Raw) {
			return nil, nil, fmt.Errorf("did:x509 x5c header must be sorted from leaf- to root certificate")
		}
	}
	// Step 4. Apply any further application-specific checks, for example disallowing insecure certificate signature algorithms.
	//         Skipped: this check is already performed by Verfiable Credential interaction using PEX: Presentation Definitions should limit the accepted CAs through ca-fingerprint constraining.
	// Step 5. Map the certificate chain to the JSON data model.
	//         Note: this isn't implemented by unmarshalling into a JSON model, but by parsing the DID into X509DidReference.
	ref, err := ParseX509Did(id)
	if err != nil {
		return nil, nil, err
	}
	// Sanity check: ca-fingerprint must refer to a CA certificate
	caFingerprintCert, err := findCertificateByHash(chain, ref.CAFingerprint, ref.Method)
	if err != nil {
		return nil, nil, err
	}
	if !caFingerprintCert.IsCA {
		return nil, nil, fmt.Errorf("did:x509 ca-fingerprint refers to leaf certificate, must be either root or intermediate CA certificate")
	}
	// Step 6. Check whether the DID is valid against the certificate chain in the JSON data model according to the Rego policy (or equivalent rules) defined in this document.
	//         Note: this isn't implemented by unmarshalling into a JSON model and Rego, but by parsing the DID and checking the policies against the signing certificate.
	err = validatePolicy(ref, validationCert)
	if err != nil {
		return nil, nil, err
	}

	// Step 7 to 12: Create DID Document
	document, err := createDidDocument(id, validationCert)
	if err != nil {
		return nil, nil, err
	}
	// Step 13. Return the complete DID document.
	return document, &resolver.DocumentMetadata{}, err
}

// createDidDocument generates a new DID Document based on the provided DID identifier and validation certificate.
func createDidDocument(id did.DID, validationCert *x509.Certificate) (*did.Document, error) {
	didUrl := did.DIDURL{DID: id, Fragment: "0"}
	// Step 7. Extract the public key of the first certificate in the chain.
	publicKey := validationCert.PublicKey
	// Step 8. Convert the public key to a JSON Web Key.
	verificationMethod, err := did.NewVerificationMethod(didUrl, ssi.JsonWebKey2020, id, publicKey)
	if err != nil {
		return nil, err
	}
	// Step 9. Create the following partial DID document:
	document := &did.Document{
		Context: []interface{}{
			ssi.MustParseURI("https://www.w3.org/ns/did/v1"),
		},
		ID:                 id,
		Controller:         []did.DID{id},
		VerificationMethod: did.VerificationMethods{verificationMethod},
	}
	// Step 10. If the first certificate in the chain has the key usage bit position for digitalSignature set or is missing the key usage extension, add the following to the DID document:
	if validationCert.KeyUsage == 0 || validationCert.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
		document.AddAssertionMethod(verificationMethod)
	}
	// Step 11. If the first certificate in the chain has the key usage bit position for keyAgreement set or is missing the key usage extension, add the following to the DID document:
	if validationCert.KeyUsage == 0 || validationCert.KeyUsage&x509.KeyUsageKeyAgreement != 0 {
		document.AddKeyAgreement(verificationMethod)
	}
	// Step 12. If the first certificate in the chain includes the key usage extension but has neither digitalSignature nor keyAgreement set as key usage bits, fail.
	if validationCert.KeyUsage != 0 && validationCert.KeyUsage&x509.KeyUsageDigitalSignature == 0 && validationCert.KeyUsage&x509.KeyUsageKeyAgreement == 0 {
		return nil, errors.New("did:x509 certificate must have either digitalSignature or keyAgreement set as key usage bits")
	}
	return document, nil
}

// ParseX509Did parses a DID (Decentralized Identifier) in the x509 format and returns a corresponding X509DidReference.
func ParseX509Did(id did.DID) (*X509DidReference, error) {
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
