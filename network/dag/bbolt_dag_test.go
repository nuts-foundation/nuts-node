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
	"errors"
	"math/rand"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/jws"
	"github.com/nuts-foundation/nuts-node/test/io"
	"go.etcd.io/bbolt"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/stretchr/testify/assert"
)

// trackingVisitor just keeps track of which nodes were visited in what order.
type trackingVisitor struct {
	transactions []Transaction
}

func (n *trackingVisitor) Accept(_ context.Context, transaction Transaction) bool {
	n.transactions = append(n.transactions, transaction)
	return true
}

func (n trackingVisitor) JoinRefsAsString() string {
	var contents []string
	for _, transaction := range n.transactions {
		val := strings.TrimLeft(transaction.PayloadHash().String(), "0")
		if val == "" {
			val = "0"
		}
		contents = append(contents, val)
	}
	return strings.Join(contents, ", ")
}

func TestBBoltDAG_FindBetween(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctx := context.Background()
		graph := CreateDAG(t)

		// tx1 and tx2's signing time are out-of-order
		tx1 := CreateSignedTestTransaction(2, time.Now().AddDate(0, 0, 1), nil, "unit/test", true)
		tx2 := CreateSignedTestTransaction(1, time.Now(), nil, "unit/test", true, tx1)
		_ = graph.Add(ctx, tx1)
		_ = graph.Add(ctx, tx2)

		actual, err := graph.FindBetween(ctx, time.Now().AddDate(0, 0, -2), time.Now().AddDate(1, 0, 0))
		if !assert.NoError(t, err) {
			return
		}
		assert.Len(t, actual, 2)
		assert.Equal(t, tx1.Data(), actual[0].Data())
		assert.Equal(t, tx2.Data(), actual[1].Data())
	})
}

func TestBBoltDAG_findBetweenLC(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctx := context.Background()
		graph := CreateDAG(t)

		// tx1 < [tx2, tx3] < tx4 < tx5
		tx1 := CreateSignedTestTransaction(1, time.Now(), nil, "unit/test", true)
		tx2 := CreateSignedTestTransaction(2, time.Now(), nil, "unit/test", true, tx1)
		tx3 := CreateSignedTestTransaction(3, time.Now(), nil, "unit/test", true, tx1)
		tx4 := CreateSignedTestTransaction(4, time.Now(), nil, "unit/test", true, tx2, tx3)
		tx5 := CreateSignedTestTransaction(5, time.Now(), nil, "unit/test", true, tx4)
		err := graph.Add(ctx, tx1, tx2, tx3, tx4, tx5)
		if !assert.NoError(t, err) {
			return
		}

		// LC 1..3 should yield tx2, tx3 and tx4
		actual, err := graph.findBetweenLC(ctx, 1, 3)

		if !assert.NoError(t, err) {
			return
		}
		assert.Len(t, actual, 3)
		assert.Contains(t, actual, tx2)
		assert.Contains(t, actual, tx3)
		assert.Contains(t, actual, tx4)
	})
}

func TestBBoltDAG_Get(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		ctx := context.Background()
		graph := CreateDAG(t)
		transaction := CreateTestTransactionWithJWK(1)
		_ = graph.Add(ctx, transaction)
		actual, err := graph.Get(ctx, transaction.Ref())
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, transaction, actual)
	})
	t.Run("not found", func(t *testing.T) {
		ctx := context.Background()
		graph := CreateDAG(t)
		actual, err := graph.Get(ctx, hash.SHA256Sum([]byte{1, 2, 3}))
		assert.NoError(t, err)
		assert.Nil(t, actual)
	})
	t.Run("bbolt byte slice is copied", func(t *testing.T) {
		// This test the fixing of https://github.com/nuts-foundation/nuts-node/issues/488: "Fix and debug strange memory corruption issue".
		// It was caused by using a []byte returned from BBolt after the TX was closed (parsing it as JWS), which is illegal.
		// It happened when there was concurrent read/write access to BBolt (e.g. adding and reading TXs concurrently).
		graph := CreateDAG(t)
		// Create root TX
		rootTX := CreateTestTransactionWithJWK(0)
		graph.Add(context.Background(), rootTX)
		// Create and read TXs in parallel to trigger error scenario
		const numTX = 10
		wg := sync.WaitGroup{}
		wg.Add(numTX)
		for i := 0; i < numTX; i++ {
			go func() {
				defer wg.Done()
				cxt := context.Background()
				tx := CreateTestTransactionWithJWK(uint32(rand.Int31n(100000)), rootTX)
				if !assert.NoError(t, graph.Add(cxt, tx)) {
					return
				}
				actual, err := graph.Get(cxt, tx.Ref())
				if !assert.NoError(t, err) {
					return
				}
				_, err = jws.Parse(actual.Data())
				if !assert.NoError(t, err) {
					return
				}
			}()
		}
		wg.Wait()
	})
}

func TestBBoltDAG_Add(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctx := context.Background()
		graph := CreateDAG(t)
		tx := CreateTestTransactionWithJWK(0)

		err := graph.Add(ctx, tx)

		assert.NoError(t, err)
		visitor := trackingVisitor{}
		err = graph.Walk(ctx, visitor.Accept, hash.EmptyHash())
		if !assert.NoError(t, err) {
			return
		}
		assert.Len(t, visitor.transactions, 1)
		assert.Equal(t, tx.Ref(), visitor.transactions[0].Ref())
		present, _ := graph.IsPresent(ctx, tx.Ref())
		assert.True(t, present)
	})
	t.Run("duplicate", func(t *testing.T) {
		ctx := context.Background()
		graph := CreateDAG(t)
		tx := CreateTestTransactionWithJWK(0)

		_ = graph.Add(ctx, tx)
		err := graph.Add(ctx, tx)

		assert.NoError(t, err)
		// Assert we can find the TX, but make sure it's only there once
		actual, _ := graph.FindBetween(ctx, MinTime(), MaxTime())
		assert.Len(t, actual, 1)
	})
	t.Run("second root", func(t *testing.T) {
		ctx := context.Background()
		graph := CreateDAG(t)
		root1 := CreateTestTransactionWithJWK(1)
		root2 := CreateTestTransactionWithJWK(2)

		_ = graph.Add(ctx, root1)
		err := graph.Add(ctx, root2)
		assert.EqualError(t, err, "root transaction already exists")
		actual, _ := graph.FindBetween(ctx, MinTime(), MaxTime())
		assert.Len(t, actual, 1)
	})
	t.Run("error - cyclic graph", func(t *testing.T) {
		t.Skip("Algorithm for detecting cycles is not yet decided on")
		// A -> B -> C -> B
		ctx := context.Background()
		A := CreateTestTransactionWithJWK(0)
		B := CreateTestTransactionWithJWK(1, A).(*transaction)
		C := CreateTestTransactionWithJWK(2, B)
		B.prevs = append(B.prevs, C.Ref())

		graph := CreateDAG(t)
		err := graph.Add(ctx, A, B, C)
		assert.EqualError(t, err, "")
	})
}

func TestNewBBoltDAG_addToLCIndex(t *testing.T) {
	// These three transactions come with a clock value.
	A := CreateTestTransactionWithJWK(0)
	B := CreateTestTransactionWithJWK(1, A)
	C := CreateTestTransactionWithJWK(2, B)
	// This one doesn't
	D := CreateLegacyTransactionWithJWK(3, C)

	assertRefs := func(t *testing.T, tx *bbolt.Tx, clock uint32, expected []hash.SHA256Hash) {
		lcBucket, _ := tx.CreateBucketIfNotExists([]byte(clockBucket))

		ref := lcBucket.Get(clockToBytes(clock))
		if !assert.NotNil(t, ref) {
			return
		}

		refs := parseHashList(ref)
		sort.Slice(refs, func(i, j int) bool {
			return refs[i].Compare(refs[j]) <= 0
		})
		sort.Slice(expected, func(i, j int) bool {
			return expected[i].Compare(expected[j]) <= 0
		})

		assert.Equal(t, len(expected), len(refs))
		for i := range refs {
			assert.True(t, refs[i].Equals(expected[i]))
		}
	}
	assertClock := func(t *testing.T, tx *bbolt.Tx, clock uint32, expected hash.SHA256Hash) {
		lcIndexBucket, _ := tx.CreateBucketIfNotExists([]byte(clockIndexBucket))

		clockBytes := lcIndexBucket.Get(expected.Slice())
		if !assert.NotNil(t, clockBytes) {
			return
		}

		assert.Equal(t, clock, bytesToClock(clockBytes))
	}

	t.Run("Ok threesome", func(t *testing.T) {
		testDirectory := io.TestDirectory(t)
		db := createBBoltDB(testDirectory)

		err := db.Update(func(tx *bbolt.Tx) error {
			_ = indexClockValue(tx, A)
			_ = indexClockValue(tx, B)
			_ = indexClockValue(tx, C)
			_ = indexClockValue(tx, D)

			assertRefs(t, tx, 0, []hash.SHA256Hash{A.Ref()})
			assertClock(t, tx, 0, A.Ref())
			assertRefs(t, tx, 1, []hash.SHA256Hash{B.Ref()})
			assertClock(t, tx, 1, B.Ref())
			assertRefs(t, tx, 2, []hash.SHA256Hash{C.Ref()})
			assertClock(t, tx, 2, C.Ref())
			assertRefs(t, tx, 3, []hash.SHA256Hash{D.Ref()})
			assertClock(t, tx, 3, D.Ref())

			return nil
		})

		assert.NoError(t, err)
	})

	t.Run("Ok double add", func(t *testing.T) {
		testDirectory := io.TestDirectory(t)
		db := createBBoltDB(testDirectory)

		err := db.Update(func(tx *bbolt.Tx) error {
			_ = indexClockValue(tx, A)
			_ = indexClockValue(tx, B)
			_ = indexClockValue(tx, B)

			assertRefs(t, tx, 0, []hash.SHA256Hash{A.Ref()})
			assertClock(t, tx, 0, A.Ref())
			assertRefs(t, tx, 1, []hash.SHA256Hash{B.Ref()})
			assertClock(t, tx, 1, B.Ref())

			return nil
		})

		assert.NoError(t, err)
	})

	t.Run("Ok branch", func(t *testing.T) {
		testDirectory := io.TestDirectory(t)
		db := createBBoltDB(testDirectory)
		C := CreateTestTransactionWithJWK(2, A)

		err := db.Update(func(tx *bbolt.Tx) error {
			_ = indexClockValue(tx, A)
			_ = indexClockValue(tx, B)
			_ = indexClockValue(tx, C)

			assertRefs(t, tx, 0, []hash.SHA256Hash{A.Ref()})
			assertClock(t, tx, 0, A.Ref())
			assertRefs(t, tx, 1, []hash.SHA256Hash{B.Ref(), C.Ref()})
			assertClock(t, tx, 1, B.Ref())
			assertClock(t, tx, 1, C.Ref())

			return nil
		})

		assert.NoError(t, err)
	})

	t.Run("err - missing prev", func(t *testing.T) {
		testDirectory := io.TestDirectory(t)
		db := createBBoltDB(testDirectory)

		err := db.Update(func(tx *bbolt.Tx) error {
			return indexClockValue(tx, D)
		})

		assert.Error(t, err)
	})

}

func TestBBoltDAG_Migrate(t *testing.T) {
	A := CreateTestTransactionWithJWK(0)
	B := CreateTestTransactionWithJWK(1, A)
	C := CreateTestTransactionWithJWK(2, A)
	D := CreateTestTransactionWithJWK(3, A, C)

	putTransaction := func(tx *bbolt.Tx, transaction Transaction, nexts []hash.SHA256Hash) {
		// create correct buckets and add root
		txBucket, _ := tx.CreateBucketIfNotExists([]byte(transactionsBucket))
		nextBucket, _ := tx.CreateBucketIfNotExists([]byte(nextsBucket))
		txBucket.Put(transaction.Ref().Slice(), transaction.Data())
		nextBytes := []byte{}
		for _, n := range nexts {
			nextBytes = appendHashList(nextBytes, n)
		}
		nextBucket.Put(transaction.Ref().Slice(), nextBytes)
	}

	putRoot := func(tx *bbolt.Tx, transaction Transaction, nexts []hash.SHA256Hash) {
		txBucket, _ := tx.CreateBucketIfNotExists([]byte(transactionsBucket))
		txBucket.Put([]byte(rootsTransactionKey), transaction.Ref().Slice())
		putTransaction(tx, transaction, nexts)
	}

	t.Run("ok - already ran", func(t *testing.T) {
		graph := CreateDAG(t)

		err := graph.Migrate()
		if !assert.NoError(t, err) {
			return
		}
	})

	t.Run("ok - root is translated", func(t *testing.T) {
		graph := CreateDAG(t)
		graph.db.Update(func(tx *bbolt.Tx) error {
			putRoot(tx, A, []hash.SHA256Hash{})
			return nil
		})

		err := graph.Migrate()
		if !assert.NoError(t, err) {
			return
		}

		graph.db.View(func(tx *bbolt.Tx) error {
			clockBucket := tx.Bucket([]byte(clockBucket))
			root := clockBucket.Get(clockToBytes(0))
			assert.Len(t, root, 32)
			assert.Nil(t, tx.Bucket([]byte(nextsBucket)))
			return nil
		})
	})

	t.Run("ok - simple graph is translated", func(t *testing.T) {
		graph := CreateDAG(t)
		graph.db.Update(func(tx *bbolt.Tx) error {
			putRoot(tx, A, []hash.SHA256Hash{B.Ref()})
			putTransaction(tx, B, []hash.SHA256Hash{})
			return nil
		})

		err := graph.Migrate()
		if !assert.NoError(t, err) {
			return
		}

		graph.db.View(func(tx *bbolt.Tx) error {
			clockBucket := tx.Bucket([]byte(clockBucket))
			atOne := clockBucket.Get(clockToBytes(1))
			assert.Len(t, atOne, 32)
			return nil
		})
	})

	t.Run("ok - branch is translated", func(t *testing.T) {
		graph := CreateDAG(t)
		graph.db.Update(func(tx *bbolt.Tx) error {
			putRoot(tx, A, []hash.SHA256Hash{B.Ref(), C.Ref()})
			putTransaction(tx, B, []hash.SHA256Hash{})
			putTransaction(tx, C, []hash.SHA256Hash{})
			return nil
		})

		err := graph.Migrate()
		if !assert.NoError(t, err) {
			return
		}

		graph.db.View(func(tx *bbolt.Tx) error {
			clockBucket := tx.Bucket([]byte(clockBucket))
			atOne := clockBucket.Get(clockToBytes(1))
			assert.Len(t, atOne, 64)
			return nil
		})
	})

	t.Run("ok - more complicated", func(t *testing.T) {
		graph := CreateDAG(t)
		graph.db.Update(func(tx *bbolt.Tx) error {
			// create correct buckets and add root
			putRoot(tx, A, []hash.SHA256Hash{B.Ref(), C.Ref(), D.Ref()})
			putTransaction(tx, B, []hash.SHA256Hash{D.Ref()})
			putTransaction(tx, C, []hash.SHA256Hash{})
			putTransaction(tx, D, []hash.SHA256Hash{})
			return nil
		})

		err := graph.Migrate()
		if !assert.NoError(t, err) {
			return
		}

		graph.db.View(func(tx *bbolt.Tx) error {
			clockBucket := tx.Bucket([]byte(clockBucket))
			atOne := clockBucket.Get(clockToBytes(2))
			assert.Len(t, atOne, 32)
			return nil
		})
	})
}

func TestBBoltDAG_Walk(t *testing.T) {
	t.Run("ok - empty graph", func(t *testing.T) {
		ctx := context.Background()
		graph := CreateDAG(t)
		visitor := trackingVisitor{}

		err := graph.Walk(ctx, visitor.Accept, hash.EmptyHash())
		if !assert.NoError(t, err) {
			return
		}

		assert.Empty(t, visitor.transactions)
	})

	t.Run("ok - start at root for empty hash", func(t *testing.T) {
		ctx := context.Background()
		graph := CreateDAG(t)
		visitor := trackingVisitor{}
		transaction := CreateTestTransactionWithJWK(1)
		_ = graph.Add(ctx, transaction)

		err := graph.Walk(ctx, visitor.Accept, hash.EmptyHash())
		if !assert.NoError(t, err) {
			return
		}

		assert.Len(t, visitor.transactions, 1)
	})

	t.Run("ok - TXs processing in right order", func(t *testing.T) {
		ctx := context.Background()
		graph := CreateDAG(t)
		visitor := trackingVisitor{}
		A := CreateTestTransactionWithJWK(1)
		B := CreateTestTransactionWithJWK(2, A)
		C := CreateTestTransactionWithJWK(3, A)
		D := CreateTestTransactionWithJWK(4, C, B)
		_ = graph.Add(ctx, A, B, C, D)

		err := graph.Walk(ctx, visitor.Accept, hash.EmptyHash())
		if !assert.NoError(t, err) {
			return
		}

		assert.Len(t, visitor.transactions, 4)
		assert.Equal(t, A.Ref().String(), visitor.transactions[0].Ref().String())
		// the smallest byte value should have been processed first
		assert.True(t, visitor.transactions[1].Ref().Compare(visitor.transactions[2].Ref()) <= 0)
		assert.Equal(t, D.Ref().String(), visitor.transactions[3].Ref().String())
	})
}

func TestBBoltDAG_GetByPayloadHash(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		ctx := context.Background()
		graph := CreateDAG(t)
		transaction := CreateTestTransactionWithJWK(1)
		_ = graph.Add(ctx, transaction)
		actual, err := graph.GetByPayloadHash(ctx, transaction.PayloadHash())
		assert.Len(t, actual, 1)
		assert.NoError(t, err)
		assert.Equal(t, transaction, actual[0])
	})
	t.Run("not found", func(t *testing.T) {
		ctx := context.Background()
		graph := CreateDAG(t)
		actual, err := graph.GetByPayloadHash(ctx, hash.SHA256Sum([]byte{1, 2, 3}))
		assert.NoError(t, err)
		assert.Empty(t, actual)
	})
}

func TestBBoltDAG_PayloadHashes(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctx := context.Background()
		graph := CreateDAG(t)
		const numberOfTXs = 5
		payloads := make(map[hash.SHA256Hash]bool, 0)
		// Create some TXs
		rootTX := CreateTestTransactionWithJWK(0)
		payloads[rootTX.PayloadHash()] = false
		_ = graph.Add(ctx, rootTX)
		for i := 1; i < numberOfTXs; i++ {
			tx := CreateTestTransactionWithJWK(uint32(i), rootTX)
			_ = graph.Add(ctx, tx)
			payloads[tx.PayloadHash()] = false
		}

		// Call
		numCalled := 0
		err := graph.PayloadHashes(ctx, func(payloadHash hash.SHA256Hash) error {
			// Every payload should be visited once
			assert.False(t, payloads[payloadHash])
			// Mark visited
			payloads[payloadHash] = true
			numCalled++
			return nil
		})
		assert.NoError(t, err)
		assert.Equal(t, numberOfTXs, numCalled)
		// Assert all transaction payloads have been visited
		for _, b := range payloads {
			assert.True(t, b)
		}
	})
	t.Run("error - visitor returns error", func(t *testing.T) {
		ctx := context.Background()
		graph := CreateDAG(t)
		_ = graph.Add(ctx, CreateTestTransactionWithJWK(0))
		_ = graph.Add(ctx, CreateTestTransactionWithJWK(1))
		numCalled := 0
		err := graph.PayloadHashes(ctx, func(payloadHash hash.SHA256Hash) error {
			numCalled++
			return errors.New("some error")
		})
		assert.Error(t, err)
		assert.Equal(t, 1, numCalled)
	})
	t.Run("ok - empty DAG", func(t *testing.T) {
		ctx := context.Background()
		graph := CreateDAG(t)
		numCalled := 0
		err := graph.PayloadHashes(ctx, func(payloadHash hash.SHA256Hash) error {
			numCalled++
			return nil
		})
		assert.NoError(t, err)
		assert.Equal(t, 0, numCalled)
	})
}

func Test_parseHashList(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		assert.Empty(t, parseHashList([]byte{}))
	})
	t.Run("1 entry", func(t *testing.T) {
		h1 := hash.SHA256Sum([]byte("Hello, World!"))
		actual := parseHashList(h1[:])
		assert.Len(t, actual, 1)
		assert.Equal(t, hash.FromSlice(h1[:]), actual[0])
	})
	t.Run("2 entries", func(t *testing.T) {
		h1 := hash.SHA256Sum([]byte("Hello, World!"))
		h2 := hash.SHA256Sum([]byte("Hello, All!"))
		actual := parseHashList(append(h1[:], h2[:]...))
		assert.Len(t, actual, 2)
		assert.Equal(t, hash.FromSlice(h1[:]), actual[0])
		assert.Equal(t, hash.FromSlice(h2[:]), actual[1])
	})
	t.Run("2 entries, dangling bytes", func(t *testing.T) {
		h1 := hash.SHA256Sum([]byte("Hello, World!"))
		h2 := hash.SHA256Sum([]byte("Hello, All!"))
		input := append(h1[:], h2[:]...)
		input = append(input, 1, 2, 3) // Add some dangling bytes
		actual := parseHashList(input)
		assert.Len(t, actual, 2)
		assert.Equal(t, hash.FromSlice(h1[:]), actual[0])
		assert.Equal(t, hash.FromSlice(h2[:]), actual[1])
	})
}

func TestBBoltDAG_getHighestClock(t *testing.T) {
	t.Run("empty DAG", func(t *testing.T) {
		ctx := context.Background()
		graph := CreateDAG(t)

		clock := graph.getHighestClock(ctx)

		assert.Equal(t, uint32(0), clock)
	})
	t.Run("multiple transaction", func(t *testing.T) {
		ctx := context.Background()
		graph := CreateDAG(t)
		tx0, _, _ := CreateTestTransaction(9)
		tx1, _, _ := CreateTestTransaction(8, tx0)
		tx2, _, _ := CreateTestTransaction(7, tx1)
		_ = graph.Add(ctx, tx0, tx1, tx2)

		clock := graph.getHighestClock(ctx)

		assert.Equal(t, uint32(2), clock)
	})
	t.Run("out of order transactions", func(t *testing.T) {
		ctx := context.Background()
		graph := CreateDAG(t)
		tx0, _, _ := CreateTestTransaction(9)
		tx1, _, _ := CreateTestTransaction(8, tx0)
		tx2, _, _ := CreateTestTransaction(7, tx1)
		_ = graph.Add(ctx, tx0, tx2)
		_ = graph.Add(context.Background(), tx1)

		clock := graph.getHighestClock(context.Background())

		assert.Equal(t, uint32(2), clock)
	})
}
