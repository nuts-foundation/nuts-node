/*
 * Copyright (C) 2022 Nuts community
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
	"github.com/stretchr/testify/require"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nuts-foundation/nuts-node/network/dag/tree"
)

const testLeafSize = 512

func TestTree_WriteTo(t *testing.T) {
	t.Run("write tx", func(t *testing.T) {
		tx, _, _ := CreateTestTransaction(1)
		storeWrite := newTreeStore(tree.New(tree.NewXor(), testLeafSize))
		storeWrite.insert(tx)

		var buf bytes.Buffer
		require.NoError(t, storeWrite.WriteTo(&buf))

		storeRead := newTreeStore(tree.New(tree.NewXor(), testLeafSize))
		require.NoError(t, storeRead.ReadFrom(&buf))

		assert.Equal(t, tx.Ref(), storeRead.getRoot().(*tree.Xor).Hash())
		assert.Equal(t, tx.Ref(), storeWrite.getRoot().(*tree.Xor).Hash())
	})

	t.Run("ok - dropping leaves", func(t *testing.T) {
		store := newTreeStore(tree.New(tree.NewXor(), testLeafSize))
		tx1, _, _ := CreateTestTransaction(1)
		tx2, _, _ := CreateTestTransaction(2, tx1)
		tx2.(*transaction).lamportClock = testLeafSize // on second page, so tree expands
		tx3, _, _ := CreateTestTransaction(3, tx2)

		// write on first page, root == leaf
		store.insert(tx1)
		// write on second page, root + 2 leaves
		store.insert(tx2)
		// drop leaves, so root only
		store.tree.DropLeaves()
		// write to second page that is now part of root
		store.insert(tx3)

		var buf bytes.Buffer
		require.NoError(t, store.WriteTo(&buf))

		storeRead := newTreeStore(tree.New(tree.NewXor(), testLeafSize))
		require.NoError(t, storeRead.ReadFrom(&buf))

		data, _ := store.getZeroTo(0)
		assert.Equal(t, data, storeRead.getRoot())
	})
}

func TestTree_read(t *testing.T) {
	storeWrite := newTreeStore(tree.New(tree.NewXor(), testLeafSize))
	testTx := CreateTestTransactionWithJWK(123)
	testTx.(*transaction).lamportClock = testLeafSize // tx is on second page
	storeWrite.insert(testTx)

	t.Run("ok - read tree successfully", func(t *testing.T) {
		var buf bytes.Buffer
		require.NoError(t, storeWrite.WriteTo(&buf))

		store := newTreeStore(tree.New(tree.NewXor(), testLeafSize))
		require.NoError(t, store.ReadFrom(&buf))

		xor, clock := store.getZeroTo(MaxLamportClock)
		assert.Equal(t, testTx.Ref(), xor.(*tree.Xor).Hash())
		assert.Equal(t, uint32(2*testLeafSize-1), clock) // highest clock on second page
	})

	t.Run("fail - incorrect prototype", func(t *testing.T) {
		var buf bytes.Buffer
		require.NoError(t, storeWrite.WriteTo(&buf))

		store := newTreeStore(tree.New(tree.NewIblt(0), testLeafSize))
		assert.EqualError(t, store.ReadFrom(&buf), "invalid data length")
	})
}
