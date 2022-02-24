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
	crypto2 "crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lestrrat-go/jwx/jws"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vcr/signature"
	"strings"
	"time"
)

// LegacyLDProof is a simple/wrong implementation of the ldProof specification. It uses a simple canonicalization
// algorithm and base64 encodes the payload before signing. It is here for backwards compatibility.
type LegacyLDProof struct {
	vc.JSONWebSignature2020Proof
}

// NewLegacyLDProof creates a new LegacyLDProof from proofOptions
func NewLegacyLDProof(options ProofOptions) *LegacyLDProof {
	return &LegacyLDProof{
		JSONWebSignature2020Proof: vc.JSONWebSignature2020Proof{
			Proof: vc.Proof{
				ProofPurpose: options.ProofPurpose,
				Created:      options.Created,
				Domain:       options.Domain,
			},
		},
	}
}

// Verify verifies the legacy proof for correctness
// Note that the document must not contain a proof
func (p LegacyLDProof) Verify(document Document, suite signature.Suite, key crypto2.PublicKey) error {
	document["proof"] = nil

	splittedJws := strings.Split(p.Jws, "..")
	p.Jws = ""
	if len(splittedJws) != 2 {
		return errors.New("invalid 'jws' value in proof")
	}
	sig, err := base64.RawURLEncoding.DecodeString(splittedJws[1])
	if err != nil {
		return err
	}
	canonicalProof, err := json.Marshal(p)
	if err != nil {
		return err
	}

	canonicalDocument, err := suite.CanonicalizeDocument(document)
	if err != nil {
		return err
	}

	sums := append(suite.CalculateDigest(canonicalProof), suite.CalculateDigest(canonicalDocument)...)
	tbv := base64.RawURLEncoding.EncodeToString(sums)

	alg, err := nutsCrypto.SignatureAlgorithm(key)
	if err != nil {
		return err
	}

	jswVerifier, _ := jws.NewVerifier(alg)
	// the jws lib can't do this for us, so we concat hdr with payload for verification
	challenge := fmt.Sprintf("%s.%s", splittedJws[0], tbv)
	if err = jswVerifier.Verify([]byte(challenge), sig, key); err != nil {
		return fmt.Errorf("invalid proof signature: %w", err)
	}
	return nil
}

// Sign signs a provided document with the provided key.
// Deprecated: this method is the initial and wrong implementation of a JSON-LD proof. There will be a new method added in the near future.
func (p LegacyLDProof) Sign(document Document, suite signature.Suite, key nutsCrypto.Key) (interface{}, error) {
	document["proof"] = nil
	kid, err := ssi.ParseURI(key.KID())
	if err != nil {
		return nil, fmt.Errorf("unable to sign proof: unable parse KID as ssi.URI")
	}

	p.Type = suite.GetType()
	p.ProofPurpose = "assertionMethod"
	if p.Created.IsZero() {
		p.Created = time.Now()
	}
	p.VerificationMethod = *kid

	canonicalProof, err := suite.CanonicalizeDocument(p)
	if err != nil {
		return nil, err
	}

	canonicalDocument, err := suite.CanonicalizeDocument(document)
	if err != nil {
		return nil, err
	}

	sums := append(suite.CalculateDigest(canonicalProof), suite.CalculateDigest(canonicalDocument)...)
	tbs := base64.RawURLEncoding.EncodeToString(sums)

	sig, err := suite.Sign([]byte(tbs), key)
	detachedSig := p.toDetachedSignature(string(sig))
	signedDocument, err := NewSignedDocument(document)
	if err != nil {
		return nil, err
	}

	p.JSONWebSignature2020Proof.Jws = detachedSig
	proofAsMap := p.asMap()

	signedDocument["proof"] = proofAsMap

	return signedDocument, nil
}

// toDetachedSignature removes the middle part of the signature
func (LegacyLDProof) toDetachedSignature(sig string) string {
	splitted := strings.Split(sig, ".")
	return strings.Join([]string{splitted[0], splitted[2]}, "..")
}

func (p LegacyLDProof) asMap() map[string]interface{} {
	res := map[string]interface{}{}
	b, _ := json.Marshal(p)
	json.Unmarshal(b, &res)
	return res
}
