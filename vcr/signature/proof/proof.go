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
	"crypto"
	"encoding/json"
	ssi "github.com/nuts-foundation/go-did"
	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vcr/signature"
)

// Document represents the document to sign. It does not contain proofs or signatures
type Document map[string]interface{}

// SignedDocument represents a generic signed document with a proof
// It bundles helper functions to easily work with proofs.
type SignedDocument map[string]interface{}

// DocumentProof represents a generic proof
type DocumentProof map[string]interface{}

// NewSignedDocument creates a new SignedDocument from a source struct
func NewSignedDocument(source interface{}) (SignedDocument, error) {
	// Convert the source to a generic LD Signed Document
	sourceBytes, err := json.Marshal(source)
	if err != nil {
		return nil, err
	}
	result := SignedDocument{}
	if err := json.Unmarshal(sourceBytes, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// DocumentWithoutProof returns the Document without the proof.
func (d SignedDocument) DocumentWithoutProof() Document {
	docWithoutProof := Document{}
	for key, value := range d {
		if key == "proof" {
			continue
		}
		docWithoutProof[key] = value
	}
	return docWithoutProof
}

// UnmarshalProofValue unmarshalls the signature of the document in the provided target
func (d SignedDocument) UnmarshalProofValue(target interface{}) error {
	asJSON, err := json.Marshal(d["proof"])
	if err != nil {
		return err
	}
	return json.Unmarshal(asJSON, target)
}

//// FirstProof returns the first proof of a SignedDocument.
//// Since a document can contain multiple proofs, this method remove that uncertainty.
//func (d SignedDocument) FirstProof() DocumentProof {
//	rawProof, ok := d["proof"]
//	if !ok {
//		// no proof in signed document
//		return nil
//	}
//
//	if singleProof, ok := rawProof.(map[string]interface{}); ok {
//		return singleProof
//	}
//
//	if proofList, isArray := rawProof.([]interface{}); isArray {
//		if len(proofList) > 0 {
//			if firstProof, isMap := proofList[0].(map[string]interface{}); isMap {
//				return firstProof
//			}
//		}
//	}
//	return nil
//}

// ProofType returns the type of the proof
func (d SignedDocument) ProofType() *ssi.ProofType {
	proofType, ok := d["type"]
	if !ok {
		return nil
	}
	parsedType := ssi.ProofType(proofType.(string))
	return &parsedType
}

// Proof is the interface that defines a set of methods which a proof should implement.
type Proof interface {
	// Sign defines the basic signing operation on the proof.
	Sign(document Document, suite signature.Suite, key nutsCrypto.Key) (interface{}, error)
}

// ProofBuilder defines a generic interface for proof builders.
type ProofBuilder interface {
	// Sign accepts a key and returns the signed document.
	Sign(document map[string]interface{}, key nutsCrypto.Key) (interface{}, error)
}

// ProofVerifier defines the generic verifier interface
type ProofVerifier interface {
	// Verify verifies the signedDocument with the provided public key. If the document is valid, it returns no error.
	Verify(document Document, suite signature.Suite, key crypto.PublicKey) error
}
