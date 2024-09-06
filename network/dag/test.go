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
	"context"
	"crypto"
	"encoding/binary"
	"fmt"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/nuts-node/audit"
	"path"
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-node/test/io"

	"github.com/nuts-foundation/go-stoabs/bbolt"
	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
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

	var publicKey crypto.PublicKey
	kid := fmt.Sprintf("%d", payloadNum)
	key, _ := nutsCrypto.GenerateJWK()
	_ = key.Set(jwk.KeyIDKey, kid)
	jwtSigner := nutsCrypto.MemoryJWTSigner{Key: key}
	if attach {
		publicKey = jwkToCryptoPublicKey(key)
	}
	signedTransaction, err := NewTransactionSigner(jwtSigner, kid, publicKey).Sign(audit.TestContext(), unsignedTransaction, signingTime)
	if err != nil {
		panic(err)
	}
	return signedTransaction

}

func jwkToCryptoPublicKey(jwkKey jwk.Key) crypto.PublicKey {
	jwkPublicKey, _ := jwkKey.PublicKey()
	var rawKey interface{}
	if err := jwkPublicKey.Raw(&rawKey); err != nil {
		panic(err)
	}

	publicKey, ok := rawKey.(crypto.PublicKey)
	if !ok {
		panic("wrong key type")
	}

	return publicKey
}

// CreateTestTransactionEx creates a transaction with the given payload hash and signs it with a random EC key.
func CreateTestTransactionEx(num uint32, payloadHash hash.SHA256Hash, participants EncryptedPAL, prevs ...Transaction) (Transaction, string, crypto.PublicKey) {
	lamportClock := calculateLamportClock(prevs)
	unsignedTransaction, _ := NewTransaction(payloadHash, "application/did+json", prevHashes(prevs), participants, lamportClock)
	kid := fmt.Sprintf("%d", num)

	// generate new key in jwk.Key format
	key, _ := nutsCrypto.GenerateJWK()
	_ = key.Set(jwk.KeyIDKey, kid)
	publicKey := jwkToCryptoPublicKey(key)
	jwtSigner := nutsCrypto.MemoryJWTSigner{Key: key}
	signedTransaction, err := NewTransactionSigner(jwtSigner, kid, nil).Sign(audit.TestContext(), unsignedTransaction, time.Now())
	if err != nil {
		panic(err)
	}
	return signedTransaction, kid, publicKey
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

func createBBoltDB(testDirectory string) stoabs.KVStore {
	db, err := bbolt.CreateBBoltStore(path.Join(testDirectory, "dag"), stoabs.WithNoSync())
	if err != nil {
		panic(err)
	}
	return db
}

func CreateDAG(t *testing.T) *dag {
	testDirectory := io.TestDirectory(t)
	d := newDAG(createBBoltDB(testDirectory))
	return d
}

// addTx is a helper to add transactions to the DAG. It creates an Update bbolt TX and panics the test on error
func addTx(t *testing.T, graph *dag, transactions ...Transaction) {
	err := addTxErr(graph, transactions...)
	if err != nil {
		t.Fatal(err)
	}
}

// addTx is a helper to add transactions to the DAG. It creates an Update bbolt TX and returns the error
func addTxErr(graph *dag, transactions ...Transaction) error {
	return graph.db.Write(context.Background(), func(tx stoabs.WriteTx) error {
		return graph.add(tx, transactions...)
	})
}
