/*
 * Copyright (C) 2021. Nuts community
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

package dag

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"time"
)


// CreateTestDocumentWithJWK creates a document with the given num as payload hash and signs it with a random EC key.
// The JWK is attached, rather than referred to using the kid.
func CreateTestDocumentWithJWK(num uint32, prevs ...hash.SHA256Hash) Document {
	payloadHash := hash.SHA256Hash{}
	binary.BigEndian.PutUint32(payloadHash[hash.SHA256HashSize-4:], num)
	unsignedDocument, _ := NewDocument(payloadHash, "foo/bar", prevs)
	signer := newTestSigner()
	signedDocument, err := NewAttachedJWKDocumentSigner(signer, fmt.Sprintf("%d", num), signer).Sign(unsignedDocument, time.Now())
	if err != nil {
		panic(err)
	}
	return signedDocument
}

// CreateTestDocument creates a document with the given num as payload hash and signs it with a random EC key.
func CreateTestDocument(num uint32, prevs ...hash.SHA256Hash) (Document, string, crypto.PublicKey) {
	payloadHash := hash.SHA256Hash{}
	binary.BigEndian.PutUint32(payloadHash[hash.SHA256HashSize-4:], num)
	unsignedDocument, _ := NewDocument(payloadHash, "foo/bar", prevs)
	signer := newTestSigner()
	kid := fmt.Sprintf("%d", num)
	signedDocument, err := NewDocumentSigner(signer, kid).Sign(unsignedDocument, time.Now())
	if err != nil {
		panic(err)
	}
	return signedDocument, kid, signer.key.Public()
}

func newTestSigner() *testSigner {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return &testSigner{key: key}
}

type testSigner struct {
	key crypto.Signer
}

func (t testSigner) SavePublicKey(_ string, _ crypto.PublicKey, _ core.Period) error {
	panic("implement me")
}

func (t testSigner) GetPublicKey(_ string, _ time.Time) (crypto.PublicKey, error) {
	return t.key.Public(), nil
}

func (t *testSigner) SignJWS(payload []byte, protectedHeaders map[string]interface{}, _ string) (string, jwa.SignatureAlgorithm, error) {
	hdrs := jws.NewHeaders()
	for k, v := range protectedHeaders {
		if err := hdrs.Set(k, v); err != nil {
			return "", "", err
		}
	}
	sig, _ := jws.Sign(payload, jwa.ES256, t.key, jws.WithHeaders(hdrs))
	return string(sig), jwa.ES256, nil
}
