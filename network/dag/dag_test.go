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
	"bytes"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
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
	t.Run("ok", func(t *testing.T) {
		graph := newDAG()

		// tx1 < [tx2, tx3] < tx4 < tx5
		tx1 := CreateSignedTestTransaction(1, time.Now(), nil, "unit/test", true)
		tx2 := CreateSignedTestTransaction(2, time.Now(), nil, "unit/test", true, tx1)
		tx3 := CreateSignedTestTransaction(3, time.Now(), nil, "unit/test", true, tx1)
		tx4 := CreateSignedTestTransaction(4, time.Now(), nil, "unit/test", true, tx2, tx3)
		tx5 := CreateSignedTestTransaction(5, time.Now(), nil, "unit/test", true, tx4)
		require.NoError(t, graph.addTx(tx1))
		require.NoError(t, graph.addTx(tx2))
		require.NoError(t, graph.addTx(tx3))
		require.NoError(t, graph.addTx(tx4))
		require.NoError(t, graph.addTx(tx5))

		// LC 1..3 should yield tx2, tx3 and tx4
		actual := graph.findBetweenLC(1, 3)
		assert.Len(t, actual, 3)
		assert.Contains(t, actual, tx2)
		assert.Contains(t, actual, tx3)
		assert.Contains(t, actual, tx4)
	})
}

func TestDAG_TxByHash(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		graph := newDAG()
		transaction := CreateTestTransactionWithJWK(1)
		require.NoError(t, graph.addTx(transaction))
		actual, err := graph.txByHash(transaction.Ref())
		require.NoError(t, err)
		assert.Equal(t, transaction, actual)
	})
	t.Run("not found", func(t *testing.T) {
		graph := newDAG()
		actual, err := graph.txByHash(hash.SHA256Sum([]byte{1, 2, 3}))
		assert.ErrorIs(t, err, ErrTransactionNotFound)
		assert.Nil(t, actual)
	})
}

func TestDAG_AddTx(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		graph := newDAG()
		tx := CreateTestTransactionWithJWK(0)
		require.NoError(t, graph.addTx(tx))

		visitor := trackingVisitor{}
		graph.visitBetweenLC(0, 1, visitor.Accept)
		assert.Len(t, visitor.transactions, 1)
		assert.Equal(t, tx.Ref(), visitor.transactions[0].Ref())
		assert.True(t, graph.containsTxHash(tx.Ref()))
	})
	t.Run("updates metadata", func(t *testing.T) {
		graph := newDAG()
		tx1 := CreateTestTransactionWithJWK(0)
		tx2 := CreateTestTransactionWithJWK(1, tx1)
		require.NoError(t, graph.addTx(tx1))
		require.NoError(t, graph.addTx(tx2))

		assert.Equal(t, tx2.Ref(), graph.headTxHash())
		assert.Equal(t, 1, graph.highestLamportClock())
		assert.Equal(t, 2, graph.txCount())
	})
	t.Run("duplicate", func(t *testing.T) {
		graph := newDAG()
		tx := CreateTestTransactionWithJWK(0)
		require.NoError(t, graph.addTx(tx))

		actual := graph.findBetweenLC(0, MaxLamportClock)
		assert.Len(t, actual, 1)
	})
	t.Run("second root", func(t *testing.T) {
		graph := newDAG()
		root1 := CreateTestTransactionWithJWK(1)
		root2 := CreateTestTransactionWithJWK(2)
		require.NoError(t, graph.addTx(root1))
		assert.EqualError(t, graph.addTx(root2), "root transaction already exists")
		actual := graph.findBetweenLC(0, MaxLamportClock)
		assert.Len(t, actual, 1)
	})
}

func TestNewDAG_LCIndex(t *testing.T) {
	assertClockIndex := func(t *testing.T, graph *dag, clock int, txs ...Transaction) {
		// pointer comparison difficult, so copy in here
		var got, want []hash.SHA256Hash
		for _, p := range graph.hashesPerClock[clock] {
			got = append(got, *p)
		}
		for _, tx := range txs {
			want = append(want, tx.Ref())
		}
		sort.Slice(want, func(i, j int) bool {
			return bytes.Compare(want[i][:], want[j][:]) < 0
		})
		assert.Equal(t, got, want)
	}

	t.Run("Ok threesome", func(t *testing.T) {
		a := CreateTestTransactionWithJWK(0)
		b := CreateTestTransactionWithJWK(1, a)
		c := CreateTestTransactionWithJWK(2, b)

		graph := newDAG()
		require.NoError(t, graph.addTx(a))
		require.NoError(t, graph.addTx(b))
		require.NoError(t, graph.addTx(c))

		require.Equal(t, len(graph.hashesPerClock), 3)
		assertClockIndex(t, graph, 0, a)
		assertClockIndex(t, graph, 1, b)
		assertClockIndex(t, graph, 2, c)
	})

	t.Run("Ok double add", func(t *testing.T) {
		a := CreateTestTransactionWithJWK(0)
		b := CreateTestTransactionWithJWK(1, a)

		graph := newDAG()
		require.NoError(t, graph.addTx(a))
		require.NoError(t, graph.addTx(b))
		require.NoError(t, graph.addTx(b))

		require.Equal(t, len(graph.hashesPerClock), 2)
		assertClockIndex(t, graph, 0, a)
		assertClockIndex(t, graph, 1, b)
	})

	t.Run("OK branch", func(t *testing.T) {
		a := CreateTestTransactionWithJWK(0)
		b := CreateTestTransactionWithJWK(1, a)
		c := CreateTestTransactionWithJWK(2, a)

		graph := newDAG()
		require.NoError(t, graph.addTx(a))
		require.NoError(t, graph.addTx(b))
		require.NoError(t, graph.addTx(c))

		require.Equal(t, len(graph.hashesPerClock), 2)
		assertClockIndex(t, graph, 0, a)
		assertClockIndex(t, graph, 1, b, c)
	})
}

func TestDAG_highestLamportClock(t *testing.T) {
	t.Run("empty DAG", func(t *testing.T) {
		graph := newDAG()
		assert.Equal(t, -1, graph.highestLamportClock())
	})

	t.Run("multiple transaction", func(t *testing.T) {
		tx0, _, _ := CreateTestTransaction(9)
		tx1, _, _ := CreateTestTransaction(8, tx0)
		tx2, _, _ := CreateTestTransaction(7, tx1)
		graph := newDAG()
		require.NoError(t, graph.addTx(tx0))
		require.NoError(t, graph.addTx(tx1))
		require.NoError(t, graph.addTx(tx2))
		assert.Equal(t, 2, graph.highestLamportClock())
	})

	t.Run("out of order transactions", func(t *testing.T) {
		t.Skip("TODO(pascaldekloe): Not sure what the out-of-order test tries to do. Are we supposed to allow clock gaps with graph insertion? @gerard")
		tx0, _, _ := CreateTestTransaction(9)
		tx1, _, _ := CreateTestTransaction(8, tx0)
		tx2, _, _ := CreateTestTransaction(7, tx1)
		graph := newDAG()
		require.NoError(t, graph.addTx(tx0))
		require.NoError(t, graph.addTx(tx2))
		require.NoError(t, graph.addTx(tx1))
		assert.Equal(t, 2, graph.highestLamportClock())
	})
}
