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
	"encoding/binary"
	"fmt"
	crypto2 "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"time"
)

// CreateTestDocumentWithJWK creates a document with the given num as payload hash and signs it with a random EC key.
// The JWK is attached, rather than referred to using the kid.
func CreateTestDocumentWithJWK(num uint32, prevs ...hash.SHA256Hash) Document {
	payloadHash := hash.SHA256Hash{}
	binary.BigEndian.PutUint32(payloadHash[hash.SHA256HashSize-4:], num)
	unsignedDocument, _ := NewDocument(payloadHash, "foo/bar", prevs)
	signer := crypto2.NewTestSigner()
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
	signer := crypto2.NewTestSigner()
	kid := fmt.Sprintf("%d", num)
	signedDocument, err := NewDocumentSigner(signer, kid).Sign(unsignedDocument, time.Now())
	if err != nil {
		panic(err)
	}
	return signedDocument, kid, signer.Key.Public()
}

// graphF creates the following graph:
//..................A
//................/  \
//...............B    C
//...............\   / \
//.................D    E
//.......................\
//........................F
func graphF() []Document {
	A := CreateTestDocumentWithJWK(0)
	B := CreateTestDocumentWithJWK(1, A.Ref())
	C := CreateTestDocumentWithJWK(2, A.Ref())
	D := CreateTestDocumentWithJWK(3, B.Ref(), C.Ref())
	E := CreateTestDocumentWithJWK(4, C.Ref())
	F := CreateTestDocumentWithJWK(5, E.Ref())
	return []Document{A, B, C, D, E, F}
}

// graphG creates the following graph:
//..................A
//................/  \
//...............B    C
//...............\   / \
//.................D    E
//.................\.....\
//..................\.....F
//...................\.../
//.....................G
func graphG() []Document {
	docs := graphF()
	g := CreateTestDocumentWithJWK(6, docs[3].Ref(), docs[5].Ref())
	docs = append(docs, g)
	return docs
}
