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
	"context"
	"fmt"
	"github.com/lestrrat-go/jwx/v2/jws"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/piprate/json-gold/ld"
)

// JSONWebSignature2020 Contains the correct implementation of the JSONWebSignature2020 signature suite
// It bundles the correct implementation of the canonicalize, hash and sign operations.
type JSONWebSignature2020 struct {
	ContextLoader ld.DocumentLoader
	Signer        crypto.JWTSigner
}

// Sign signs the document as a JWS.
func (s JSONWebSignature2020) Sign(ctx context.Context, doc []byte, key crypto.Key) ([]byte, error) {
	headers := detachedJWSHeaders()
	headers[jws.KeyIDKey] = key.KID()
	sig, err := s.Signer.SignJWS(ctx, doc, headers, key, true)
	return []byte(sig), err
}

// CanonicalizeDocument canonicalizes a document using the LD canonicalization algorithm.
// Can be used for both the LD proof as the document. It requires the document to have a valid context.
func (s JSONWebSignature2020) CanonicalizeDocument(doc interface{}) ([]byte, error) {
	res, err := jsonld.LDUtil{LDDocumentLoader: s.ContextLoader}.Canonicalize(doc)
	if err != nil {
		return nil, fmt.Errorf("canonicalization failed: %w", err)
	}
	return []byte(res.(string)), nil
}

// CalculateDigest calculates the digest of the document. This implementation uses the SHA256 sum.
func (s JSONWebSignature2020) CalculateDigest(doc []byte) []byte {
	return hash.SHA256Sum(doc).Slice()
}

// GetType returns the signature type, 'JSONWebSignature2020'
func (s JSONWebSignature2020) GetType() ssi.ProofType {
	return ssi.JsonWebSignature2020
}

// detachedJWSHeaders returns headers for JSONWebSignature2020
// the alg will be based upon the key
// {"b64":false,"crit":["b64"]}
func detachedJWSHeaders() map[string]interface{} {
	return map[string]interface{}{
		"b64":  false,
		"crit": []string{"b64"},
	}
}
