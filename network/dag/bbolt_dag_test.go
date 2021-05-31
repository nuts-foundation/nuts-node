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
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/stretchr/testify/assert"
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

func TestBBoltDAG_FindBetween(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		graph := CreateDAG(t)
		tx := CreateTestTransactionWithJWK(1)

		err := graph.Add(tx)

		if !assert.NoError(t, err) {
			return
		}

		actual, err := graph.FindBetween(time.Now().AddDate(0, 0, -1), time.Now().AddDate(1, 0, 0))
		if !assert.NoError(t, err) {
			return
		}
		assert.Len(t, actual, 1)
		assert.Equal(t, tx, actual[0])
	})
}

func TestBBoltDAG_Get(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		graph := CreateDAG(t)
		transaction := CreateTestTransactionWithJWK(1)
		_ = graph.Add(transaction)
		actual, err := graph.Get(transaction.Ref())
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, transaction, actual)
	})
	t.Run("not found", func(t *testing.T) {
		graph := CreateDAG(t)
		actual, err := graph.Get(hash.SHA256Sum([]byte{1, 2, 3}))
		assert.NoError(t, err)
		assert.Nil(t, actual)
	})
}

func TestBBoltDAG_Add(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		graph := CreateDAG(t)
		tx := CreateTestTransactionWithJWK(0)

		err := graph.Add(tx)

		assert.NoError(t, err)
		visitor := trackingVisitor{}
		root, _ := graph.Root()
		err = graph.Walk(NewBFSWalkerAlgorithm(), visitor.Accept, root)
		if !assert.NoError(t, err) {
			return
		}
		assert.Len(t, visitor.transactions, 1)
		assert.Equal(t, tx.Ref(), visitor.transactions[0].Ref())
		present, _ := graph.IsPresent(tx.Ref())
		assert.True(t, present)
	})
	t.Run("duplicate", func(t *testing.T) {
		graph := CreateDAG(t)
		tx := CreateTestTransactionWithJWK(0)

		_ = graph.Add(tx)
		err := graph.Add(tx)
		assert.NoError(t, err)
		actual, _ := graph.FindBetween(MinTime(), MaxTime())
		assert.Len(t, actual, 1)
	})
	t.Run("second root", func(t *testing.T) {
		graph := CreateDAG(t)
		root1 := CreateTestTransactionWithJWK(1)
		root2 := CreateTestTransactionWithJWK(2)

		_ = graph.Add(root1)
		err := graph.Add(root2)
		assert.EqualError(t, err, "root transaction already exists")
		actual, _ := graph.FindBetween(MinTime(), MaxTime())
		assert.Len(t, actual, 1)
	})
	t.Run("ok - out of order", func(t *testing.T) {
		graph := CreateDAG(t)
		transactions := graphF()

		for i := len(transactions) - 1; i >= 0; i-- {
			err := graph.Add(transactions[i])
			if !assert.NoError(t, err) {
				return
			}
		}

		visitor := trackingVisitor{}
		root, _ := graph.Root()
		err := graph.Walk(NewBFSWalkerAlgorithm(), visitor.Accept, root)
		if !assert.NoError(t, err) {
			return
		}
		assert.Regexp(t, "0, (1, 2|2, 1), (3, 4|4, 3), 5", visitor.JoinRefsAsString())
	})
	t.Run("error - verifier failed", func(t *testing.T) {
		graph := CreateDAG(t, func(_ Transaction, _ DAG) error {
			return errors.New("failed")
		})
		tx := CreateTestTransactionWithJWK(0)

		err := graph.Add(tx)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "transaction verification failed")
		present, err := graph.IsPresent(tx.Ref())
		assert.NoError(t, err)
		assert.False(t, present)
	})
	t.Run("error - cyclic graph", func(t *testing.T) {
		t.Skip("Algorithm for detecting cycles is not yet decided on")
		// A -> B -> C -> B
		A := CreateTestTransactionWithJWK(0)
		B := CreateTestTransactionWithJWK(1, A.Ref()).(*transaction)
		C := CreateTestTransactionWithJWK(2, B.Ref())
		B.prevs = append(B.prevs, C.Ref())

		graph := CreateDAG(t)
		err := graph.Add(A, B, C)
		assert.EqualError(t, err, "")
	})
}

func TestBBoltDAG_Walk(t *testing.T) {
	t.Run("ok - empty graph", func(t *testing.T) {
		graph := CreateDAG(t)
		visitor := trackingVisitor{}

		root, _ := graph.Root()
		err := graph.Walk(NewBFSWalkerAlgorithm(), visitor.Accept, root)
		if !assert.NoError(t, err) {
			return
		}

		assert.Empty(t, visitor.transactions)
	})
}

func TestBBoltDAG_Observe(t *testing.T) {
	graph := CreateDAG(t)
	var actual interface{}
	graph.RegisterObserver(func(subject interface{}) {
		actual = subject
	})
	expected := CreateTestTransactionWithJWK(1)
	err := graph.Add(expected)
	assert.NoError(t, err)
	assert.Equal(t, expected, actual)
}

func TestBBoltDAG_GetByPayloadHash(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		graph := CreateDAG(t)
		transaction := CreateTestTransactionWithJWK(1)
		_ = graph.Add(transaction)
		actual, err := graph.GetByPayloadHash(transaction.PayloadHash())
		assert.Len(t, actual, 1)
		assert.NoError(t, err)
		assert.Equal(t, transaction, actual[0])
	})
	t.Run("not found", func(t *testing.T) {
		graph := CreateDAG(t)
		actual, err := graph.GetByPayloadHash(hash.SHA256Sum([]byte{1, 2, 3}))
		assert.NoError(t, err)
		assert.Empty(t, actual)
	})
}

func TestBBoltDAG_Diagnostics(t *testing.T) {
	dag := CreateDAG(t).(*bboltDAG)
	doc1 := CreateTestTransactionWithJWK(2)
	dag.Add(doc1)
	diagnostics := dag.Diagnostics()
	assert.Len(t, diagnostics, 3)
	// Assert actual diagnostics
	lines := make([]string, 0)
	for _, diagnostic := range diagnostics {
		lines = append(lines, diagnostic.Name()+": "+diagnostic.Outcome())
	}
	sort.Strings(lines)
	actual := strings.Join(lines, "\n")
	assert.Equal(t, `[DAG] Heads: [`+doc1.Ref().String()+`]
[DAG] Number of transactions: 1
[DAG] Stored transaction size (bytes): 8192`, actual)
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
