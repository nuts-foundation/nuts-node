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
	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vcr/signature"
)

// Document represents the document to sign.
type Document map[string]interface{}

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

type ProofVerifier interface {
	// Verify verifies the signedDocument with the provided public key. If the document is valid, it returns no error.
	Verify(signedDocument interface{}, key crypto.PublicKey) error
}
