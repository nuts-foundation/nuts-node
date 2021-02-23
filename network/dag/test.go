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
	"time"

	crypto2 "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
)

// CreateTestTransactionWithJWK creates a transaction with the given num as payload hash and signs it with a random EC key.
// The JWK is attached, rather than referred to using the kid.
func CreateTestTransactionWithJWK(num uint32, prevs ...hash.SHA256Hash) Transaction {
	payloadHash := hash.SHA256Hash{}
	binary.BigEndian.PutUint32(payloadHash[hash.SHA256HashSize-4:], num)
	unsignedTransaction, _ := NewTransaction(payloadHash, "foo/bar", prevs)
	signer := crypto2.NewTestSigner()
	signedTransaction, err := NewAttachedJWKTransactionSigner(signer, fmt.Sprintf("%d", num), signer.Key.Public()).Sign(unsignedTransaction, time.Now())
	if err != nil {
		panic(err)
	}
	return signedTransaction
}

// CreateTestTransaction creates a transaction with the given num as payload hash and signs it with a random EC key.
func CreateTestTransaction(num uint32, prevs ...hash.SHA256Hash) (Transaction, string, crypto.PublicKey) {
	payloadHash := hash.SHA256Hash{}
	binary.BigEndian.PutUint32(payloadHash[hash.SHA256HashSize-4:], num)
	unsignedTransaction, _ := NewTransaction(payloadHash, "foo/bar", prevs)
	signer := crypto2.NewTestSigner()
	kid := fmt.Sprintf("%d", num)
	signedTransaction, err := NewTransactionSigner(signer, kid).Sign(unsignedTransaction, time.Now())
	if err != nil {
		panic(err)
	}
	return signedTransaction, kid, signer.Key.Public()
}

// graphF creates the following graph:
//..................A
//................/  \
//...............B    C
//...............\   / \
//.................D    E
//.......................\
//........................F
func graphF() []Transaction {
	A := CreateTestTransactionWithJWK(0)
	B := CreateTestTransactionWithJWK(1, A.Ref())
	C := CreateTestTransactionWithJWK(2, A.Ref())
	D := CreateTestTransactionWithJWK(3, B.Ref(), C.Ref())
	E := CreateTestTransactionWithJWK(4, C.Ref())
	F := CreateTestTransactionWithJWK(5, E.Ref())
	return []Transaction{A, B, C, D, E, F}
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
func graphG() []Transaction {
	docs := graphF()
	g := CreateTestTransactionWithJWK(6, docs[3].Ref(), docs[5].Ref())
	docs = append(docs, g)
	return docs
}
