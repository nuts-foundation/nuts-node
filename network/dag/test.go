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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"time"
)

var privateKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

// CreateTestDocument creates a document witth the given num as payload hash and signs it with a random EC key.
func CreateTestDocument(num uint32, prevs ...hash.SHA256Hash) Document {
	payloadHash := hash.SHA256Hash{}
	binary.BigEndian.PutUint32(payloadHash[hash.SHA256HashSize-4:], num)
	unsignedDocument, _ := NewDocument(payloadHash, "foo/bar", prevs)
	signedDocument, err := NewDocumentSigner(&testSigner{}, fmt.Sprintf("%d", num)).Sign(unsignedDocument, time.Now())
	if err != nil {
		panic(err)
	}
	return signedDocument
}

type testSigner struct {

}

func (t testSigner) SignJWS(payload []byte, protectedHeaders map[string]interface{}, _ string) (string, error) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	hdrs := jws.NewHeaders()
	for k, v := range protectedHeaders {
		if err := hdrs.Set(k, v); err != nil {
			return "", err
		}
	}
	sig, _ := jws.Sign(payload, jwa.ES256, privateKey, jws.WithHeaders(hdrs))
	return string(sig), nil
}

