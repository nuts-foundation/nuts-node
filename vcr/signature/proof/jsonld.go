/*
 * Copyright (C) 2022 Nuts community
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

package proof

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jws"
	ssi "github.com/nuts-foundation/go-did"
	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vcr/signature"
)

// RsaSignature2018 contains the string value for the RsaSignature2018 signature type
const RsaSignature2018 = ssi.ProofType("RsaSignature2018")

// EcdsaSecp256k1Signature2019 contains the string value for the EcdsaSecp256k1Signature2019 signature type
const EcdsaSecp256k1Signature2019 = ssi.ProofType("EcdsaSecp256k1Signature2019")

// AssertionMethodProofPurpose contains the string value for the assertionMethod proof purpose
const AssertionMethodProofPurpose = "assertionMethod"

// AuthenticationProofPurpose contains the string value for the authentication proof purpose
const AuthenticationProofPurpose = "authentication"

// ProofOptions contains the options for a specific proof.
type ProofOptions struct {
	// Created contains the date and time of signing. When not set, the current date time will be used.
	Created time.Time `json:"created"`
	// Domain property is used to associate a domain with a proof
	// https://w3c-ccg.github.io/security-vocab/#domain
	Domain *string `json:"domain,omitempty"`
	//The challenge property is used to associate a challenge with a proof
	// https://w3c-ccg.github.io/security-vocab/#challenge
	Challenge *string `json:"challenge,omitempty"`
	// The Expires property is used to associate an expiration date with a proof
	Expires *time.Time `json:"expires,omitempty"`
	// ProofPurpose contains a specific intent for the proof, the reason why an entity created it.
	// Acts as a safeguard to prevent the proof from being misused for a purpose other than the one it was intended for.
	ProofPurpose string `json:"proofPurpose"`
	// Nonce contains a value that is used to prevent replay attacks
	Nonce *string `json:"nonce,omitempty"`
}

// ValidAt checks if the proof is valid at a certain given time.
func (o ProofOptions) ValidAt(at time.Time, maxSkew time.Duration) bool {
	// check if issuanceDate is before validAt
	if o.Created.After(at.Add(maxSkew)) {
		return false
	}

	// check if expirationDate is after validAt
	if o.Expires != nil && o.Expires.Add(maxSkew).Before(at) {
		return false
	}
	return true
}

// LDProof contains the fields of the Proof data model: https://w3c-ccg.github.io/data-integrity-spec/#proofs
type LDProof struct {
	ProofOptions
	// Type contains the signature type. Its is determined from the key type.
	Type ssi.ProofType `json:"type"`
	// VerificationMethod is the key identifier for the public/private key pair used to sign this proof
	// should be resolvable, e.g. did:nuts:123#key-1
	VerificationMethod ssi.URI `json:"verificationMethod"`
	// proofValue holds the representation of the proof value.
	// This can be several keys, dependent on the suite like jws, proofValue or signatureValue
	//proofValue map[string]interface{}
	JWS        string      `json:"jws,omitempty"`
	ProofValue interface{} `json:"proofValue,omitempty"`
	Signature  interface{} `json:"signature,omitempty"`
}

// NewLDProof creates a new LDProof from the ProofOptions param
func NewLDProof(options ProofOptions) *LDProof {
	return &LDProof{ProofOptions: options}
}

// Verify verifies the correctness of the signature value in the LDProof given a document, signature suite and a public key.
// Note that the document must not contain a proof
func (p LDProof) Verify(document Document, suite signature.Suite, key crypto.PublicKey) error {
	canonicalDocument, err := suite.CanonicalizeDocument(document)
	if err != nil {
		return err
	}

	preparedProof, err := p.asCanonicalizableMap()
	if err != nil {
		return err
	}
	canonicalProof, err := suite.CanonicalizeDocument(preparedProof)
	if err != nil {
		return fmt.Errorf("unable to canonicalize proof: %w", err)
	}

	tbv := append(suite.CalculateDigest(canonicalProof), suite.CalculateDigest(canonicalDocument)...)
	// the proof must be correct
	alg, err := nutsCrypto.SignatureAlgorithm(key)
	if err != nil {
		return err
	}

	jswVerifier, _ := jws.NewVerifier(alg)
	// the jws lib can't do this for us, so we concat hdr with payload for verification
	splittedJws := strings.Split(p.JWS, "..")
	if len(splittedJws) != 2 {
		return errors.New("invalid 'jws' value in proof")
	}
	sig, err := base64.RawURLEncoding.DecodeString(splittedJws[1])
	if err != nil {
		return fmt.Errorf("could not base64 decode signature: %w", err)
	}
	challenge := fmt.Sprintf("%s.%s", splittedJws[0], tbv)
	if err = jswVerifier.Verify([]byte(challenge), sig, key); err != nil {
		return fmt.Errorf("invalid proof signature: %w", err)
	}
	return nil
}

// Sign signs the provided document with this proof and a signature suite and signer.
// It returns the complete signed JSON-LD document
func (p *LDProof) Sign(ctx context.Context, document Document, suite signature.Suite, key nutsCrypto.Key) (interface{}, error) {
	p.Type = suite.GetType()
	if len(p.ProofPurpose) == 0 {
		p.ProofPurpose = AssertionMethodProofPurpose
	}
	if p.Created.IsZero() {
		p.Created = time.Now()
	}
	p.VerificationMethod = ssi.MustParseURI(key.KID())

	canonicalDocument, err := suite.CanonicalizeDocument(document)
	if err != nil {
		return nil, err
	}

	proofMap, err := p.asCanonicalizableMap()
	if err != nil {
		return nil, err
	}

	canonicalProof, err := suite.CanonicalizeDocument(proofMap)
	if err != nil {
		return nil, fmt.Errorf("unable to canonicalize proof: %w", err)
	}

	tbs := append(suite.CalculateDigest(canonicalProof), suite.CalculateDigest(canonicalDocument)...)

	sig, err := suite.Sign(ctx, tbs, key)
	if err != nil {
		return nil, fmt.Errorf("error while signing: %w", err)
	}

	p.JWS = string(sig)

	signedDocument, err := NewSignedDocument(document)
	if err != nil {
		return nil, err
	}
	signedDocument["@context"] = jsonld.AddContext(signedDocument["@context"], determineProofContext(suite.GetType()))
	proofAsMap, err := p.asMap()
	if err != nil {
		return nil, err
	}

	signedDocument["proof"] = proofAsMap
	return signedDocument, nil
}

// asCanonicalizableMap converts the proof to a map, adds a ld-context and removes the signature value so it can be canonicalized.
func (p LDProof) asCanonicalizableMap() (map[string]interface{}, error) {
	asMap, err := p.asMap()
	asMap["@context"] = jsonld.AddContext(asMap["@context"], determineProofContext(p.Type))
	asMap["@type"] = asMap["type"]
	if err != nil {
		return nil, err
	}
	proofWithoutSignature := map[string]interface{}{}
	for key, value := range asMap {
		if key == "jws" || key == "signature" || key == "proofValue" {
			continue
		}
		proofWithoutSignature[key] = value
	}
	return proofWithoutSignature, nil
}

// asMap is a helper method to easily convert a LDProof to a map.
func (p LDProof) asMap() (map[string]interface{}, error) {
	proofBytes, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	proofMap := map[string]interface{}{}
	if err := json.Unmarshal(proofBytes, &proofMap); err != nil {
		return nil, err
	}
	return proofMap, nil
}

func determineProofContext(proofType ssi.ProofType) ssi.URI {
	switch proofType {
	case RsaSignature2018:
		return signature.W3idSecurityV2Context
	case ssi.JsonWebSignature2020:
		return signature.JSONWebSignature2020Context
	case EcdsaSecp256k1Signature2019:
		return signature.W3idSecurityV1Context
	default:
		return ssi.URI{}
	}
}
