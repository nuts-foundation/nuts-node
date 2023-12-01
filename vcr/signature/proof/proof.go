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
	"errors"
	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vcr/signature"
	"reflect"
)

// Document represents the document to sign. It does not contain proofs or signatures
type Document map[string]interface{}

// SignedDocument represents a generic signed document with a proof
// It bundles helper functions to easily work with proofs.
type SignedDocument map[string]interface{}

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

// UnmarshalProofValue unmarshalls the signature of the document into the provided target.
// JSON-LD allows proof it be a compacted array (proof as JSON object instead of JSON array with objects).
// It handles this gracefully: if the target is a slice, it will unmarshal the proof as a slice.
// If the target is not a slice it will unmarshal the first element of the proof as the target,
// or return an error if the proof to be unmarshalled contains more than one element.
func (d SignedDocument) UnmarshalProofValue(target interface{}) error {
	src := d["proof"]
	// if target is a slice, make sure the proof is unmarshalled as a slice
	if isPtrSlice(target) {
		// target is a slice
		if _, ok := d["proof"].([]interface{}); !ok {
			// unmarshal target is a slice, but proof is not. Make it a slice.
			src = []interface{}{d["proof"]}
		}
	} else {
		if srcAsSlice, ok := d["proof"].([]interface{}); ok {
			if len(srcAsSlice) > 1 {
				return errors.New("tried to unmarshal multiple JSON-LD proofs into a single value, which is impossible")
			}
			if len(srcAsSlice) == 0 {
				return errors.New("no proof")
			}
			// just take first element
			src = srcAsSlice[0]
		}
	}
	asJSON, err := json.Marshal(src)
	if err != nil {
		return err
	}
	return json.Unmarshal(asJSON, &target)
}

// Proof is the interface that defines a set of methods which a proof should implement.
type Proof interface {
	// Sign defines the basic signing operation on the proof.
	Sign(document Document, suite signature.Suite, key nutsCrypto.Key) (interface{}, error)
}

// ProofVerifier defines the generic verifier interface
type ProofVerifier interface {
	// Verify verifies the Document with the provided public key. If the document is valid, it returns no error.
	Verify(document Document, suite signature.Suite, key crypto.PublicKey) error
}

func isPtrSlice(i interface{}) bool {
	// Taken from https://stackoverflow.com/questions/69675420/how-to-check-if-interface-is-a-a-pointer-to-a-slice
	if i == nil {
		return false
	}
	v := reflect.ValueOf(i)
	if v.Kind() != reflect.Ptr {
		return false
	}
	return v.Elem().Kind() == reflect.Slice
}
