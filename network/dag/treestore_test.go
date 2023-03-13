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
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/stretchr/testify/assert"

	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/nuts-node/network/dag/tree"
	"github.com/nuts-foundation/nuts-node/test/io"
)

const testLeafSize = 512

func TestTree_write(t *testing.T) {
	ctx := context.Background()
	t.Run("write tx", func(t *testing.T) {
		db := createBBoltDB(io.TestDirectory(t))
		storeWrite := newTreeStore("observer bucket", tree.New(tree.NewXor(), testLeafSize))
		storeRead := newTreeStore("observer bucket", tree.New(tree.NewXor(), testLeafSize))
		tx, _, _ := CreateTestTransaction(1)

		err := db.Write(ctx, func(dbTx stoabs.WriteTx) error {
			return storeWrite.write(dbTx, tx)
		})
		require.NoError(t, err)
		err = db.Read(ctx, func(tx stoabs.ReadTx) error {
			return storeRead.read(tx)
		})
		require.NoError(t, err)

		assert.Equal(t, tx.Ref(), storeRead.getRoot().(*tree.Xor).Hash())
		assert.Equal(t, tx.Ref(), storeWrite.getRoot().(*tree.Xor).Hash())
	})

	t.Run("ok - dropping leaves", func(t *testing.T) {
		db := createBBoltDB(io.TestDirectory(t))
		store := newTreeStore("xor drop leaves", tree.New(tree.NewXor(), testLeafSize))
		tx1, _, _ := CreateTestTransaction(1)
		tx2, _, _ := CreateTestTransaction(2, tx1)
		tx2.(*transaction).lamportClock = testLeafSize // on second page, so tree expands
		tx3, _, _ := CreateTestTransaction(3, tx2)

		err := db.Write(ctx, func(dbTx stoabs.WriteTx) error {
			// write on first page, root == leaf
			if err := store.write(dbTx, tx1); err != nil {
				return err
			}
			// write on second page, root + 2 leaves
			if err := store.write(dbTx, tx2); err != nil {
				return err
			}
			// drop leaves, so root only
			store.tree.DropLeaves()
			// write to second page that is now part of root
			return store.write(dbTx, tx3)
		})
		assert.NoError(t, err)

		storeRead := newTreeStore("xor drop leaves", tree.New(tree.NewXor(), testLeafSize))
		_ = db.Read(ctx, func(tx stoabs.ReadTx) error {
			return storeRead.read(tx)
		})

		data, _ := store.getZeroTo(0)
		assert.Equal(t, data, storeRead.getRoot())
	})
}

func TestTree_read(t *testing.T) {
	db := createBBoltDB(io.TestDirectory(t))
	ctx := context.Background()
	storeWrite := newTreeStore("real bucket", tree.New(tree.NewXor(), testLeafSize))
	testTx := CreateTestTransactionWithJWK(123)
	testTx.(*transaction).lamportClock = testLeafSize // tx is on second page
	err := db.Write(ctx, func(tx stoabs.WriteTx) error {
		return storeWrite.write(tx, testTx)
	})
	require.NoError(t, err)

	t.Run("ok - read tree successfully", func(t *testing.T) {
		store := newTreeStore("real bucket", tree.New(tree.NewXor(), testLeafSize))

		err := db.Read(ctx, func(tx stoabs.ReadTx) error {
			return store.read(tx)
		})

		xor, clock := store.getZeroTo(MaxLamportClock)
		assert.NoError(t, err)
		assert.Equal(t, testTx.Ref(), xor.(*tree.Xor).Hash())
		assert.Equal(t, uint32(2*testLeafSize-1), clock) // highest clock on second page
	})

	t.Run("ok - incorrect bucket name results in empty tree", func(t *testing.T) {
		store := newTreeStore("fake bucket", tree.New(tree.NewXor(), testLeafSize))

		err := db.Read(ctx, func(tx stoabs.ReadTx) error {
			return store.read(tx)
		})

		assert.NoError(t, err)
		assert.Equal(t, tree.Data(tree.NewXor()), store.getRoot())
	})

	t.Run("fail - incorrect prototype", func(t *testing.T) {
		store := newTreeStore("real bucket", tree.New(tree.NewIblt(0), testLeafSize))

		err := db.Read(ctx, func(tx stoabs.ReadTx) error {
			return store.read(tx)
		})

		assert.EqualError(t, err, "invalid data length")
	})
}
