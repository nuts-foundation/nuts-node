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
	"fmt"
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
		tx1 := CreateSignedTestTransaction(2, time.Now().AddDate(0, 0, 1), "unit/test", true)
		tx2 := CreateSignedTestTransaction(1, time.Now(), "unit/test", true, tx1.Ref())
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
		rootTX := CreateTestTransactionWithJWK(uint32(0))
		graph.Add(context.Background(), rootTX)
		// Create and read TXs in parallel to trigger error scenario
		const numTX = 10
		wg := sync.WaitGroup{}
		wg.Add(numTX)
		for i := 0; i < numTX; i++ {
			go func() {
				defer wg.Done()
				cxt := context.Background()
				tx := CreateTestTransactionWithJWK(uint32(rand.Int31n(100000)), rootTX.Ref())
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
		root, _ := graph.Root(ctx)
		err = graph.Walk(ctx, visitor.Accept, root)
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
	//t.Run("ok - out of order", func(t *testing.T) {
	//	ctx := context.Background()
	//	graph := CreateDAG(t)
	//	transactions := graphF()
	//
	//	for i := len(transactions) - 1; i >= 0; i-- {
	//		err := graph.Add(ctx, transactions[i])
	//		if !assert.NoError(t, err) {
	//			return
	//		}
	//	}
	//
	//	visitor := trackingVisitor{}
	//	root, _ := graph.Root(ctx)
	//	err := graph.Walk(ctx, NewBFSWalkerAlgorithm(), visitor.Accept, root)
	//	if !assert.NoError(t, err) {
	//		return
	//	}
	//	assert.Regexp(t, "0, (1, 2|2, 1), (3, 4|4, 3), 5", visitor.JoinRefsAsString())
	//})
	t.Run("error - verifier failed", func(t *testing.T) {
		ctx := context.Background()
		graph := CreateDAG(t, func(_ context.Context, _ Transaction, _ DAG) error {
			return errors.New("failed")
		})
		tx := CreateTestTransactionWithJWK(0)

		err := graph.Add(ctx, tx)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "transaction verification failed")
		present, err := graph.IsPresent(ctx, tx.Ref())
		assert.NoError(t, err)
		assert.False(t, present)
	})
	t.Run("error - cyclic graph", func(t *testing.T) {
		t.Skip("Algorithm for detecting cycles is not yet decided on")
		// A -> B -> C -> B
		ctx := context.Background()
		A := CreateTestTransactionWithJWK(0)
		B := CreateTestTransactionWithJWK(1, A.Ref()).(*transaction)
		C := CreateTestTransactionWithJWK(2, B.Ref())
		B.prevs = append(B.prevs, C.Ref())

		graph := CreateDAG(t)
		err := graph.Add(ctx, A, B, C)
		assert.EqualError(t, err, "")
	})
}

func TestNewBBoltDAG_addToLCIndex(t *testing.T) {
	A := CreateTestTransactionWithJWK(0)
	B := CreateTestTransactionWithJWK(1, A.Ref())
	C := CreateTestTransactionWithJWK(2, B.Ref())

	assertRefs := func(t *testing.T, tx *bbolt.Tx, clock uint32, expected []hash.SHA256Hash) {
		lcBucket, _ := tx.CreateBucketIfNotExists([]byte(lcBucket))

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

		assert.Equal(t, len(refs), len(expected))
		for i := range refs {
			assert.True(t, refs[i].Equals(expected[i]))
		}
	}
	assertClock := func(t *testing.T, tx *bbolt.Tx, clock uint32, expected hash.SHA256Hash) {
		lcIndexBucket, _ := tx.CreateBucketIfNotExists([]byte(lcIndexBucket))

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
			lcBucket, _ := tx.CreateBucketIfNotExists([]byte(lcBucket))
			lcIndexBucket , _ := tx.CreateBucketIfNotExists([]byte(lcIndexBucket))

			_ = addToLCIndex(lcBucket, lcIndexBucket, A)
			_ = addToLCIndex(lcBucket, lcIndexBucket, B)
			_ = addToLCIndex(lcBucket, lcIndexBucket, C)

			assertRefs(t, tx, 0, []hash.SHA256Hash{A.Ref()})
			assertClock(t, tx, 0, A.Ref())
			assertRefs(t, tx, 1, []hash.SHA256Hash{B.Ref()})
			assertClock(t, tx, 1, B.Ref())
			assertRefs(t, tx, 2, []hash.SHA256Hash{C.Ref()})
			assertClock(t, tx, 2, C.Ref())

			return nil
		})

		assert.NoError(t, err)
	})

	t.Run("Ok branch", func(t *testing.T) {
		testDirectory := io.TestDirectory(t)
		db := createBBoltDB(testDirectory)
		C := CreateTestTransactionWithJWK(2, A.Ref())

		err := db.Update(func(tx *bbolt.Tx) error {
			lcBucket, _ := tx.CreateBucketIfNotExists([]byte(lcBucket))
			lcIndexBucket , _ := tx.CreateBucketIfNotExists([]byte(lcIndexBucket))

			_ = addToLCIndex(lcBucket, lcIndexBucket, A)
			_ = addToLCIndex(lcBucket, lcIndexBucket, B)
			_ = addToLCIndex(lcBucket, lcIndexBucket, C)

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
			lcBucket, _ := tx.CreateBucketIfNotExists([]byte(lcBucket))
			lcIndexBucket , _ := tx.CreateBucketIfNotExists([]byte(lcIndexBucket))

			return addToLCIndex(lcBucket, lcIndexBucket, B)
		})

		assert.Error(t, err)
	})

}

func TestBBoltDAG_Walk(t *testing.T) {
	t.Run("ok - empty graph", func(t *testing.T) {
		ctx := context.Background()
		graph := CreateDAG(t)
		visitor := trackingVisitor{}

		root, _ := graph.Root(ctx)
		err := graph.Walk(ctx, visitor.Accept, root)
		if !assert.NoError(t, err) {
			return
		}

		assert.Empty(t, visitor.transactions)
	})
}

func TestBBoltDAG_Observe(t *testing.T) {
	ctx := context.Background()
	graph := CreateDAG(t)
	var actual interface{}
	graph.RegisterObserver(func(ctx context.Context, subject interface{}) {
		actual = subject
	})
	expected := CreateTestTransactionWithJWK(1)
	err := graph.Add(ctx, expected)
	assert.NoError(t, err)
	assert.Equal(t, expected, actual)
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
			tx := CreateTestTransactionWithJWK(uint32(i), rootTX.Ref())
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

func TestBBoltDAG_Diagnostics(t *testing.T) {
	ctx := context.Background()
	dag := CreateDAG(t).(*bboltDAG)
	doc1 := CreateTestTransactionWithJWK(2)
	dag.Add(ctx, doc1)
	diagnostics := dag.Diagnostics()
	assert.Len(t, diagnostics, 3)
	// Assert actual diagnostics
	lines := make([]string, 0)
	for _, diagnostic := range diagnostics {
		lines = append(lines, diagnostic.Name()+": "+diagnostic.String())
	}
	sort.Strings(lines)

	dbSize := dag.Statistics(context.Background())
	assert.NotZero(t, dbSize)

	actual := strings.Join(lines, "\n")
	expected := fmt.Sprintf(`[DAG] Heads: [`+doc1.Ref().String()+`]
[DAG] Number of transactions: 1
[DAG] Stored database size (bytes): %d`, dbSize.DataSize)
	assert.Equal(t, expected, actual)
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
