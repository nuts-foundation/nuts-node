/*
 * Copyright (C) 2021 Nuts community
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
	"path"
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-node/test/io"
	"go.etcd.io/bbolt"

	crypto2 "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
)

// CreateTestTransactionWithJWK creates a transaction with the given num as payload hash and signs it with a random EC key.
// The JWK is attached, rather than referred to using the kid.
func CreateTestTransactionWithJWK(num uint32, prevs ...Transaction) Transaction {
	return CreateSignedTestTransaction(num, time.Now(), nil, "application/did+json", true, prevs...)
}

// CreateSignedTestTransaction creates a signed transaction with more control
func CreateSignedTestTransaction(payloadNum uint32, signingTime time.Time, pal [][]byte, payloadType string, attach bool, prevs ...Transaction) Transaction {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, payloadNum)
	payloadHash := hash.SHA256Sum(payload)
	lamportClock := calculateLamportClock(prevs)
	unsignedTransaction, _ := NewTransaction(payloadHash, payloadType, prevHashes(prevs), pal, lamportClock)

	signer := crypto2.NewTestKey(fmt.Sprintf("%d", payloadNum))
	signedTransaction, err := NewTransactionSigner(signer, attach).Sign(unsignedTransaction, signingTime)
	if err != nil {
		panic(err)
	}
	return signedTransaction

}

// CreateLegacyTransactionWithJWK creates a transaction with the given num as payload hash and signs it with a random EC key.
// The JWK is attached, rather than referred to using the kid.
// Deprecated: remove when V1 transactions are no longer possible
func CreateLegacyTransactionWithJWK(num uint32, prevs ...Transaction) Transaction {
	return CreateSignedLegacyTransaction(num, time.Now(), nil, "application/did+json", true, prevs...)
}

// CreateSignedLegacyTransaction creates a signed transaction with more control
// Deprecated: remove when V1 transactions are no longer possible
func CreateSignedLegacyTransaction(payloadNum uint32, signingTime time.Time, pal [][]byte, payloadType string, attach bool, prevs ...Transaction) Transaction {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, payloadNum)
	payloadHash := hash.SHA256Sum(payload)
	unsignedTransaction, _ := NewTransaction(payloadHash, payloadType, prevHashes(prevs), pal, 0)

	signer := crypto2.NewTestKey(fmt.Sprintf("%d", payloadNum))
	signedTransaction, err := NewTransactionSigner(signer, attach).Sign(unsignedTransaction, signingTime)
	if err != nil {
		panic(err)
	}
	return signedTransaction

}

// CreateTestTransactionEx creates a transaction with the given payload hash and signs it with a random EC key.
func CreateTestTransactionEx(num uint32, payloadHash hash.SHA256Hash, participants EncryptedPAL, prevs ...Transaction) (Transaction, string, crypto.PublicKey) {
	lamportClock := calculateLamportClock(prevs)
	unsignedTransaction, _ := NewTransaction(payloadHash, "application/did+json", prevHashes(prevs), participants, lamportClock)
	kid := fmt.Sprintf("%d", num)
	signer := crypto2.NewTestKey(kid)
	signedTransaction, err := NewTransactionSigner(signer, false).Sign(unsignedTransaction, time.Now())
	if err != nil {
		panic(err)
	}
	return signedTransaction, kid, signer.Public()
}

// CreateTestTransaction creates a transaction with the given num as payload hash and signs it with a random EC key.
func CreateTestTransaction(num uint32, prevs ...Transaction) (Transaction, string, crypto.PublicKey) {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, num)
	payloadHash := hash.SHA256Sum(payload)
	return CreateTestTransactionEx(num, payloadHash, nil, prevs...)
}

func prevHashes(prevs []Transaction) []hash.SHA256Hash {
	hashes := make([]hash.SHA256Hash, len(prevs))
	for i, prev := range prevs {
		hashes[i] = prev.Ref()
	}
	return hashes
}

func calculateLamportClock(prevs []Transaction) uint32 {
	if len(prevs) == 0 {
		return 0
	}

	var clock uint32
	for _, prev := range prevs {
		// GetTransaction always supplies an LC value, either calculated or stored
		if prev.Clock() > clock {
			clock = prev.Clock()
		}
	}

	return clock + 1
}

func createBBoltDB(testDirectory string) *bbolt.DB {
	options := *bbolt.DefaultOptions
	options.NoSync = true
	db, err := bbolt.Open(path.Join(testDirectory, "dag.db"), 0600, &options)
	if err != nil {
		panic(err)
	}
	return db
}

func CreateDAG(t *testing.T) *bboltDAG {
	testDirectory := io.TestDirectory(t)
	return newBBoltDAG(createBBoltDB(testDirectory))
}
