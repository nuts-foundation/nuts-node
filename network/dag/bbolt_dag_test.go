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
	"github.com/nuts-foundation/go-stoabs"
	"math"
	"math/rand"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/jws"
	"github.com/stretchr/testify/assert"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/test/io"
)

// trackingVisitor just keeps track of which nodes were visited in what order.
type trackingVisitor struct {
	transactions []Transaction
}

func (n *trackingVisitor) Accept(transaction Transaction) bool {
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

func TestBBoltDAG_findBetweenLC(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		graph := CreateDAG(t)

		// tx1 < [tx2, tx3] < tx4 < tx5
		tx1 := CreateSignedTestTransaction(1, time.Now(), nil, "unit/test", true)
		tx2 := CreateSignedTestTransaction(2, time.Now(), nil, "unit/test", true, tx1)
		tx3 := CreateSignedTestTransaction(3, time.Now(), nil, "unit/test", true, tx1)
		tx4 := CreateSignedTestTransaction(4, time.Now(), nil, "unit/test", true, tx2, tx3)
		tx5 := CreateSignedTestTransaction(5, time.Now(), nil, "unit/test", true, tx4)
		addTx(t, graph, tx2, tx3, tx4, tx5)

		// LC 1..3 should yield tx2, tx3 and tx4
		err := graph.db.Read(func(tx stoabs.ReadTx) error {
			actual, err := graph.findBetweenLC(tx, 1, 3)

			if !assert.NoError(t, err) {
				return nil
			}
			assert.Len(t, actual, 3)
			assert.Contains(t, actual, tx2)
			assert.Contains(t, actual, tx3)
			assert.Contains(t, actual, tx4)
			return nil
		})
		assert.NoError(t, err)
	})
}

func TestBBoltDAG_Get(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		graph := CreateDAG(t)
		transaction := CreateTestTransactionWithJWK(1)
		_ = graph.db.Write(func(tx stoabs.WriteTx) error {
			_ = graph.add(tx, transaction)
			actual, err := getTransaction(transaction.Ref(), tx)
			if !assert.NoError(t, err) {
				return err
			}
			assert.Equal(t, transaction, actual)
			return nil
		})
	})
	t.Run("not found", func(t *testing.T) {
		graph := CreateDAG(t)
		_ = graph.db.Write(func(tx stoabs.WriteTx) error {
			actual, err := getTransaction(hash.SHA256Sum([]byte{1, 2, 3}), tx)
			assert.NoError(t, err)
			assert.Nil(t, actual)
			return nil
		})
	})
	t.Run("bbolt byte slice is copied", func(t *testing.T) {
		// This test the fixing of https://github.com/nuts-foundation/nuts-node/issues/488: "Fix and debug strange memory corruption issue".
		// It was caused by using a []byte returned from BBolt after the TX was closed (parsing it as JWS), which is illegal.
		// It happened when there was concurrent read/write access to BBolt (e.g. adding and reading TXs concurrently).
		graph := CreateDAG(t)
		// Create root TX
		rootTX := CreateTestTransactionWithJWK(0)
		addTx(t, graph, rootTX)
		// Create and read TXs in parallel to trigger error scenario
		const numTX = 10
		wg := sync.WaitGroup{}
		wg.Add(numTX)
		for i := 0; i < numTX; i++ {
			go func() {
				defer wg.Done()
				tx1 := CreateTestTransactionWithJWK(uint32(rand.Int31n(100000)), rootTX)
				err := graph.db.Write(func(tx stoabs.WriteTx) error {
					_ = graph.add(tx, tx1)
					actual, err := getTransaction(tx1.Ref(), tx)
					if err != nil {
						return err
					}
					_, err = jws.Parse(actual.Data())
					return err
				})
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
		graph := CreateDAG(t)
		tx := CreateTestTransactionWithJWK(0)

		addTx(t, graph, tx)

		visitor := trackingVisitor{}
		err := graph.db.Read(func(dbTx stoabs.ReadTx) error {
			return graph.walk(dbTx, 0, visitor.Accept)
		})
		if !assert.NoError(t, err) {
			return
		}
		assert.Len(t, visitor.transactions, 1)
		assert.Equal(t, tx.Ref(), visitor.transactions[0].Ref())
		err = graph.db.Read(func(dbTx stoabs.ReadTx) error {
			assert.True(t, graph.isPresent(dbTx, tx.Ref()))
			return nil
		})
		assert.NoError(t, err)
	})
	t.Run("duplicate", func(t *testing.T) {
		graph := CreateDAG(t)
		tx := CreateTestTransactionWithJWK(0)

		addTx(t, graph, tx)

		_ = graph.db.Read(func(tx stoabs.ReadTx) error {
			// Assert we can find the TX, but make sure it's only there once
			actual, _ := graph.findBetweenLC(tx, 0, math.MaxUint32)
			assert.Len(t, actual, 1)
			return nil
		})
	})
	t.Run("second root", func(t *testing.T) {
		graph := CreateDAG(t)
		root1 := CreateTestTransactionWithJWK(1)
		root2 := CreateTestTransactionWithJWK(2)

		addTx(t, graph, root1)
		err := addTxErr(graph, root2)
		assert.EqualError(t, err, "root transaction already exists")
		_ = graph.db.Read(func(tx stoabs.ReadTx) error {
			actual, _ := graph.findBetweenLC(tx, 0, math.MaxUint32)
			assert.Len(t, actual, 1)
			return nil
		})
	})
	t.Run("error - cyclic graph", func(t *testing.T) {
		t.Skip("Algorithm for detecting cycles is not yet decided on")
		// A -> B -> C -> B
		A := CreateTestTransactionWithJWK(0)
		B := CreateTestTransactionWithJWK(1, A).(*transaction)
		C := CreateTestTransactionWithJWK(2, B)
		B.prevs = append(B.prevs, C.Ref())

		graph := CreateDAG(t)
		err := addTxErr(graph, A, B, C)
		assert.EqualError(t, err, "")
	})
}

func TestNewBBoltDAG_addToLCIndex(t *testing.T) {
	// These three transactions come with a clock value.
	A := CreateTestTransactionWithJWK(0)
	B := CreateTestTransactionWithJWK(1, A)
	C := CreateTestTransactionWithJWK(2, B)

	assertRefs := func(t *testing.T, tx stoabs.ReadTx, clock uint32, expected []hash.SHA256Hash) {
		lcBucket, _ := tx.GetShelfReader(clockShelf)

		ref, _ := lcBucket.Get(stoabs.Uint32Key(clock))
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
	assertClock := func(t *testing.T, tx stoabs.ReadTx, clock uint32, expected hash.SHA256Hash) {
		lcBucket, _ := tx.GetShelfReader(clockShelf)

		hashBytes, _ := lcBucket.Get(stoabs.Uint32Key(clock))
		if !assert.NotNil(t, hashBytes) {
			return
		}
		hashes := parseHashList(hashBytes)
		assert.Contains(t, hashes, expected)
	}

	t.Run("Ok threesome", func(t *testing.T) {
		testDirectory := io.TestDirectory(t)
		db := createBBoltDB(testDirectory)

		err := db.Write(func(tx stoabs.WriteTx) error {
			_ = indexClockValue(tx, A)
			_ = indexClockValue(tx, B)
			_ = indexClockValue(tx, C)

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

	t.Run("Ok double add", func(t *testing.T) {
		testDirectory := io.TestDirectory(t)
		db := createBBoltDB(testDirectory)

		err := db.Write(func(tx stoabs.WriteTx) error {
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

		err := db.Write(func(tx stoabs.WriteTx) error {
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

}

func TestBBoltDAG_Walk(t *testing.T) {
	t.Run("ok - empty graph", func(t *testing.T) {
		graph := CreateDAG(t)
		visitor := trackingVisitor{}

		err := graph.db.Read(func(tx stoabs.ReadTx) error {
			return graph.walk(tx, 0, visitor.Accept)
		})
		if !assert.NoError(t, err) {
			return
		}

		assert.Empty(t, visitor.transactions)
	})

	t.Run("ok - start at root for empty hash", func(t *testing.T) {
		graph := CreateDAG(t)
		visitor := trackingVisitor{}
		transaction := CreateTestTransactionWithJWK(1)
		addTx(t, graph, transaction)

		err := graph.db.Read(func(tx stoabs.ReadTx) error {
			return graph.walk(tx, 0, visitor.Accept)
		})
		if !assert.NoError(t, err) {
			return
		}

		assert.Len(t, visitor.transactions, 1)
	})

	t.Run("ok - TXs processing in right order", func(t *testing.T) {
		graph := CreateDAG(t)
		visitor := trackingVisitor{}
		A := CreateTestTransactionWithJWK(1)
		B := CreateTestTransactionWithJWK(2, A)
		C := CreateTestTransactionWithJWK(3, A)
		D := CreateTestTransactionWithJWK(4, C, B)
		addTx(t, graph, A, B, C, D)

		err := graph.db.Read(func(tx stoabs.ReadTx) error {
			return graph.walk(tx, 0, visitor.Accept)
		})
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
		graph := CreateDAG(t)

		clock := graph.getHighestClock()

		assert.Equal(t, uint32(0), clock)
	})
	t.Run("multiple transaction", func(t *testing.T) {
		graph := CreateDAG(t)
		tx0, _, _ := CreateTestTransaction(9)
		tx1, _, _ := CreateTestTransaction(8, tx0)
		tx2, _, _ := CreateTestTransaction(7, tx1)
		addTx(t, graph, tx0, tx1, tx2)

		clock := graph.getHighestClock()

		assert.Equal(t, uint32(2), clock)
	})
	t.Run("out of order transactions", func(t *testing.T) {
		graph := CreateDAG(t)
		tx0, _, _ := CreateTestTransaction(9)
		tx1, _, _ := CreateTestTransaction(8, tx0)
		tx2, _, _ := CreateTestTransaction(7, tx1)
		addTx(t, graph, tx0, tx2)
		addTx(t, graph, tx1)

		clock := graph.getHighestClock()

		assert.Equal(t, uint32(2), clock)
	})
}
