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

package signature

import (
	"encoding/json"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
)

// LegacyNutsSuite is the first and wrong implementation of a JSONWebSignature.
// It is here so all the signatures set in the develop network are still valid. Must be removed in Node version 2.
type LegacyNutsSuite struct {
}

// Sign signs the provided doc and returns the signature bytes.
func (l LegacyNutsSuite) Sign(doc []byte, key crypto.Key) ([]byte, error) {
	sig, err := crypto.SignJWS(doc, detachedJWSHeaders(), key.Signer())
	return []byte(sig), err
}

// CanonicalizeDocument canonicalizes the document by marshalling it to json
func (l LegacyNutsSuite) CanonicalizeDocument(doc interface{}) ([]byte, error) {
	return json.Marshal(doc)
}

// CalculateDigest returns a digest for the doc by calculating the SHA256 hash.
func (l LegacyNutsSuite) CalculateDigest(doc []byte) []byte {
	return hash.SHA256Sum(doc).Slice()
}

// GetType returns the signature type
func (l LegacyNutsSuite) GetType() ssi.ProofType {
	return ssi.JsonWebSignature2020
}
