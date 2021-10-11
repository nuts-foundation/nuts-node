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
	"github.com/nuts-foundation/nuts-node/test/io"
	"go.etcd.io/bbolt"
	"path"
	"testing"
	"time"

	crypto2 "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
)

// CreateTestTransactionWithJWK creates a transaction with the given num as payload hash and signs it with a random EC key.
// The JWK is attached, rather than referred to using the kid.
func CreateTestTransactionWithJWK(num uint32, prevs ...hash.SHA256Hash) Transaction {
	return CreateSignedTestTransaction(num, time.Now(), "foo/bar", prevs...)
}

// CreateSignedTestTransaction creates a signed transaction with more control
// The JWK is attached, rather than referred to using the kid.
func CreateSignedTestTransaction(payloadNum uint32, signingTime time.Time, payloadType string, prevs ...hash.SHA256Hash) Transaction {
	payloadHash := hash.SHA256Hash{}
	binary.BigEndian.PutUint32(payloadHash[hash.SHA256HashSize-4:], payloadNum)
	unsignedTransaction, _ := NewTransaction(payloadHash, payloadType, prevs)
	signer := crypto2.NewTestKey(fmt.Sprintf("%d", payloadNum))
	signedTransaction, err := NewTransactionSigner(signer, true).Sign(unsignedTransaction, signingTime)
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
	kid := fmt.Sprintf("%d", num)
	signer := crypto2.NewTestKey(kid)
	signedTransaction, err := NewTransactionSigner(signer, false).Sign(unsignedTransaction, time.Now())
	if err != nil {
		panic(err)
	}
	return signedTransaction, kid, signer.Public()
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

func createBBoltDB(testDirectory string) *bbolt.DB {
	db, err := bbolt.Open(path.Join(testDirectory, "dag.db"), 0600, bbolt.DefaultOptions)
	if err != nil {
		panic(err)
	}
	return db
}

func CreateDAG(t *testing.T, verifiers ...Verifier) DAG {
	testDirectory := io.TestDirectory(t)
	return NewBBoltDAG(createBBoltDB(testDirectory), verifiers...)
}
