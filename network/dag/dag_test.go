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
	"github.com/nuts-foundation/go-stoabs"
	"github.com/stretchr/testify/require"
	"sort"
	"strings"
	"testing"
	"time"

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

func TestDAG_findBetweenLC(t *testing.T) {
	ctx := context.Background()
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
		err := graph.db.Read(ctx, func(tx stoabs.ReadTx) error {
			actual, err := graph.findBetweenLC(tx, 1, 3)

			require.NoError(t, err)
			assert.Len(t, actual, 3)
			assert.Contains(t, actual, tx2)
			assert.Contains(t, actual, tx3)
			assert.Contains(t, actual, tx4)
			return nil
		})
		assert.NoError(t, err)
	})
}

func TestDAG_Get(t *testing.T) {
	ctx := context.Background()
	t.Run("found", func(t *testing.T) {
		graph := CreateDAG(t)
		transaction := CreateTestTransactionWithJWK(1)
		_ = graph.db.Write(ctx, func(tx stoabs.WriteTx) error {
			_ = graph.add(tx, transaction)
			actual, err := getTransaction(transaction.Ref(), tx)
			require.NoError(t, err)
			assert.Equal(t, transaction, actual)
			return nil
		})
	})
	t.Run("not found", func(t *testing.T) {
		graph := CreateDAG(t)
		_ = graph.db.Write(ctx, func(tx stoabs.WriteTx) error {
			actual, err := getTransaction(hash.SHA256Sum([]byte{1, 2, 3}), tx)
			assert.ErrorIs(t, err, ErrTransactionNotFound)
			assert.Nil(t, actual)
			return nil
		})
	})
}

func TestDAG_Migrate(t *testing.T) {
	ctx := context.Background()
	txRoot := CreateTestTransactionWithJWK(0)
	tx1 := CreateTestTransactionWithJWK(1, txRoot)
	tx2 := CreateTestTransactionWithJWK(2, tx1)

	t.Run("migrate LC value and transaction count to metadata storage", func(t *testing.T) {
		graph := CreateDAG(t)

		// Setup: add transactions, remove metadata
		addTx(t, graph, txRoot, tx1, tx2)
		err := graph.db.WriteShelf(ctx, metadataShelf, func(writer stoabs.Writer) error {
			return writer.Iterate(func(key stoabs.Key, _ []byte) error {
				return writer.Delete(key)
			}, stoabs.BytesKey{})
		})
		require.NoError(t, err)

		// Check values return 0
		var stats Statistics
		var lc uint32
		_ = graph.db.Read(ctx, func(tx stoabs.ReadTx) error {
			stats = graph.statistics(tx)
			lc = graph.getHighestClockValue(tx)
			return nil
		})
		assert.Equal(t, uint(0), stats.NumberOfTransactions)
		assert.Equal(t, uint32(0), lc)

		// Migrate
		err = graph.Migrate()
		require.NoError(t, err)

		// Assert
		_ = graph.db.Read(ctx, func(tx stoabs.ReadTx) error {
			stats = graph.statistics(tx)
			lc = graph.getHighestClockValue(tx)
			return nil
		})
		assert.Equal(t, uint(3), stats.NumberOfTransactions)
		assert.Equal(t, tx2.Clock(), lc)
	})
	t.Run("migrate head to metadata storage", func(t *testing.T) {
		graph := CreateDAG(t)

		// Setup: add transactions, remove metadata, add to headsShelf
		addTx(t, graph, txRoot, tx1, tx2)
		err := graph.db.WriteShelf(ctx, metadataShelf, func(writer stoabs.Writer) error {
			return writer.Iterate(func(key stoabs.Key, _ []byte) error {
				return writer.Delete(key)
			}, stoabs.BytesKey{})
		})
		require.NoError(t, err)
		err = graph.db.WriteShelf(ctx, headsShelf, func(writer stoabs.Writer) error {
			_ = writer.Put(stoabs.BytesKey(txRoot.Ref().Slice()), []byte{1})
			_ = writer.Put(stoabs.BytesKey(tx2.Ref().Slice()), []byte{1})
			return writer.Put(stoabs.BytesKey(tx1.Ref().Slice()), []byte{1})
		})
		require.NoError(t, err)

		// Check current head is nil
		var head hash.SHA256Hash
		_ = graph.db.Read(ctx, func(tx stoabs.ReadTx) error {
			head, _ = graph.getHead(tx)
			return nil
		})
		assert.Equal(t, hash.EmptyHash(), head)

		// Migrate
		err = graph.Migrate()
		require.NoError(t, err)

		// Assert
		_ = graph.db.Read(ctx, func(tx stoabs.ReadTx) error {
			head, _ = graph.getHead(tx)
			return nil
		})
		assert.Equal(t, tx2.Ref(), head)
	})
	t.Run("nothing to migrate", func(t *testing.T) {
		graph := CreateDAG(t)
		addTx(t, graph, txRoot, tx1, tx2)

		err := graph.Migrate()
		require.NoError(t, err)

		stats := Statistics{}
		var lc uint32
		_ = graph.db.Read(ctx, func(tx stoabs.ReadTx) error {
			stats = graph.statistics(tx)
			lc = graph.getHighestClockValue(tx)
			return nil
		})
		assert.Equal(t, uint(3), stats.NumberOfTransactions)
		assert.Equal(t, tx2.Clock(), lc)
	})
}

func TestDAG_Add(t *testing.T) {
	ctx := context.Background()
	t.Run("ok", func(t *testing.T) {
		graph := CreateDAG(t)
		tx := CreateTestTransactionWithJWK(0)

		addTx(t, graph, tx)

		visitor := trackingVisitor{}
		err := graph.db.Read(ctx, func(dbTx stoabs.ReadTx) error {
			return graph.visitBetweenLC(dbTx, 0, 1, visitor.Accept)
		})
		require.NoError(t, err)
		assert.Len(t, visitor.transactions, 1)
		assert.Equal(t, tx.Ref(), visitor.transactions[0].Ref())
		err = graph.db.Read(ctx, func(dbTx stoabs.ReadTx) error {
			assert.True(t, graph.isPresent(dbTx, tx.Ref()))
			return nil
		})
		assert.NoError(t, err)
	})
	t.Run("updates metadata", func(t *testing.T) {
		graph := CreateDAG(t)
		tx1 := CreateTestTransactionWithJWK(0)
		tx2 := CreateTestTransactionWithJWK(1, tx1)

		addTx(t, graph, tx1)
		addTx(t, graph, tx2)

		err := graph.db.Read(ctx, func(dbTx stoabs.ReadTx) error {
			head, err := graph.getHead(dbTx)
			lc := graph.getHighestClockValue(dbTx)
			count := graph.getNumberOfTransactions(dbTx)

			assert.NoError(t, err)
			assert.Equal(t, tx2.Ref(), head)
			assert.Equal(t, uint32(1), lc)
			assert.Equal(t, uint64(2), count)
			return nil
		})
		assert.NoError(t, err)
	})
	t.Run("duplicate", func(t *testing.T) {
		graph := CreateDAG(t)
		tx := CreateTestTransactionWithJWK(0)

		addTx(t, graph, tx)

		_ = graph.db.Read(ctx, func(tx stoabs.ReadTx) error {
			// Assert we can find the TX, but make sure it's only there once
			actual, _ := graph.findBetweenLC(tx, 0, MaxLamportClock)
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
		_ = graph.db.Read(ctx, func(tx stoabs.ReadTx) error {
			actual, _ := graph.findBetweenLC(tx, 0, MaxLamportClock)
			assert.Len(t, actual, 1)
			return nil
		})
	})
}

func TestNewDAG_addToLCIndex(t *testing.T) {
	ctx := context.Background()

	// These three transactions come with a clock value.
	A := CreateTestTransactionWithJWK(0)
	B := CreateTestTransactionWithJWK(1, A)
	C := CreateTestTransactionWithJWK(2, B)

	assertRefs := func(t *testing.T, tx stoabs.ReadTx, clock uint32, expected []hash.SHA256Hash) {
		lcBucket := tx.GetShelfReader(clockShelf)

		ref, _ := lcBucket.Get(stoabs.Uint32Key(clock))
		require.NotNil(t, ref)

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
		lcBucket := tx.GetShelfReader(clockShelf)

		hashBytes, _ := lcBucket.Get(stoabs.Uint32Key(clock))
		require.NotNil(t, hashBytes)
		hashes := parseHashList(hashBytes)
		assert.Contains(t, hashes, expected)
	}

	t.Run("Ok threesome", func(t *testing.T) {
		testDirectory := io.TestDirectory(t)
		db := createBBoltDB(testDirectory)

		err := db.Write(ctx, func(tx stoabs.WriteTx) error {
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

		err := db.Write(ctx, func(tx stoabs.WriteTx) error {
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

		err := db.Write(ctx, func(tx stoabs.WriteTx) error {
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

func TestDAG_getHighestClock(t *testing.T) {
	ctx := context.Background()

	t.Run("empty DAG", func(t *testing.T) {
		graph := CreateDAG(t)

		_ = graph.db.Read(ctx, func(tx stoabs.ReadTx) error {
			clock := graph.getHighestClockValue(tx)

			assert.Equal(t, uint32(0), clock)
			return nil
		})
	})
	t.Run("multiple transaction", func(t *testing.T) {
		graph := CreateDAG(t)
		tx0, _, _ := CreateTestTransaction(9)
		tx1, _, _ := CreateTestTransaction(8, tx0)
		tx2, _, _ := CreateTestTransaction(7, tx1)
		addTx(t, graph, tx0, tx1, tx2)

		_ = graph.db.Read(ctx, func(tx stoabs.ReadTx) error {
			clock := graph.getHighestClockValue(tx)

			assert.Equal(t, uint32(2), clock)
			return nil
		})
	})
	t.Run("out of order transactions", func(t *testing.T) {
		graph := CreateDAG(t)
		tx0, _, _ := CreateTestTransaction(9)
		tx1, _, _ := CreateTestTransaction(8, tx0)
		tx2, _, _ := CreateTestTransaction(7, tx1)
		addTx(t, graph, tx0, tx2)
		addTx(t, graph, tx1)

		_ = graph.db.Read(ctx, func(tx stoabs.ReadTx) error {
			clock := graph.getHighestClockValue(tx)

			assert.Equal(t, uint32(2), clock)
			return nil
		})
	})
}
