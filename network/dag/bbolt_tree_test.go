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
	"encoding/binary"
	"github.com/nuts-foundation/nuts-node/test"
	"go.etcd.io/bbolt"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag/tree"
	"github.com/nuts-foundation/nuts-node/test/io"
)

const testLeafSize = 512

func TestBboltTree_writeUpdates(t *testing.T) {
	db := createBBoltDB(io.TestDirectory(t))

	t.Run("ok - inserts", func(t *testing.T) {
		store := newBBoltTreeStore(db, "xor tree", tree.New(tree.NewXor(), testLeafSize))
		store.tree.Insert(hash.FromSlice([]byte("test hash 1")), 0)
		dirty := store.tree.InsertGetDirty(hash.FromSlice([]byte("test hash 2")), testLeafSize)

		err := store.writeUpdates(context.Background(), dirty, nil)

		assert.NoError(t, err)
	})

	t.Run("ok - dropping leaves", func(t *testing.T) {
		store := newBBoltTreeStore(db, "xor drop leaves", tree.New(tree.NewXor(), testLeafSize))
		store.tree.Insert(hash.FromSlice([]byte("test hash 1")), 0)
		store.tree.Insert(hash.FromSlice([]byte("test hash 2")), testLeafSize)
		store.tree.DropLeaves()
		dirties, orphaned := store.tree.GetUpdates()

		err := store.writeUpdates(context.Background(), dirties, orphaned)
		assert.NoError(t, err)

		storeRead := newBBoltTreeStore(db, "xor drop leaves", tree.New(tree.NewXor(), testLeafSize))
		_ = storeRead.read(context.Background())

		data, _ := store.getZeroTo(0)
		assert.Equal(t, data, storeRead.getRoot())
	})
}

func TestBboltTree_read(t *testing.T) {
	db := createBBoltDB(io.TestDirectory(t))
	storeWrite := newBBoltTreeStore(db, "real bucket", tree.New(tree.NewXor(), testLeafSize))
	dirty := storeWrite.tree.InsertGetDirty(hash.FromSlice([]byte("test hash")), testLeafSize)
	err := storeWrite.writeUpdates(context.Background(), dirty, nil)
	if !assert.NoError(t, err) {
		return
	}

	t.Run("ok - read tree successfully", func(t *testing.T) {
		store := newBBoltTreeStore(db, "real bucket", tree.New(tree.NewXor(), testLeafSize))

		err := store.read(context.Background())

		assert.NoError(t, err)
		assert.Equal(t, storeWrite.getRoot(), store.getRoot())
	})

	t.Run("ok - incorrect bucket name results in empty tree", func(t *testing.T) {
		store := newBBoltTreeStore(db, "fake bucket", tree.New(tree.NewXor(), testLeafSize))

		err := store.read(context.Background())

		assert.NoError(t, err)
		assert.Equal(t, tree.Data(tree.NewXor()), store.getRoot())
	})

	t.Run("fail - incorrect prototype", func(t *testing.T) {
		store := newBBoltTreeStore(db, "real bucket", tree.New(tree.NewIblt(0), testLeafSize))

		err := store.read(context.Background())

		assert.EqualError(t, err, "invalid data length")
	})
}

func TestBboltTree_dagObserver(t *testing.T) {
	t.Run("write tx", func(t *testing.T) {
		db := createBBoltDB(io.TestDirectory(t))
		storeWrite := newBBoltTreeStore(db, "observer bucket", tree.New(tree.NewXor(), testLeafSize))
		storeRead := newBBoltTreeStore(db, "observer bucket", tree.New(tree.NewXor(), testLeafSize))
		tx, _, _ := CreateTestTransaction(1)

		storeWrite.dagObserver(context.Background(), tx, nil)
		err := storeRead.read(context.Background())
		if !assert.NoError(t, err) {
			return
		}

		assert.Equal(t, tx.Ref(), storeRead.getRoot().(*tree.Xor).Hash())
		assert.Equal(t, tx.Ref(), storeWrite.getRoot().(*tree.Xor).Hash())
	})

	t.Run("don't panic on nil Transaction", func(t *testing.T) {
		db := createBBoltDB(io.TestDirectory(t))
		store := newBBoltTreeStore(db, "observer bucket", tree.New(tree.NewXor(), testLeafSize))

		// don't panic
		store.dagObserver(context.Background(), nil, nil)
	})

	t.Run("rollback on timeout", func(t *testing.T) {
		db := createBBoltDB(io.TestDirectory(t))
		bboltTx, _ := db.Begin(true)
		ctx := context.WithValue(context.Background(), struct{}{}, bboltTx)
		store := newBBoltTreeStore(db, "observer bucket", tree.New(tree.NewXor(), testLeafSize))
		tx, _, _ := CreateTestTransaction(1)
		observerRollbackTimeOut = 10 * time.Millisecond
		defer func() {
			observerRollbackTimeOut = defaultObserverRollbackTimeOut
		}()

		currentRoutines := runtime.NumGoroutine()
		store.dagObserver(ctx, tx, nil)
		assert.Equal(t, tx.Ref(), store.getRoot().(*tree.Xor).Hash())

		test.WaitFor(t, func() (bool, error) {
			return runtime.NumGoroutine() == currentRoutines, nil
		}, 5*time.Second, "timeout while waiting for go routine to exit")
		assert.Equal(t, hash.EmptyHash(), store.getRoot().(*tree.Xor).Hash())

		_ = db.View(func(tx *bbolt.Tx) error {
			bucket := tx.Bucket([]byte("observer bucket"))
			assert.Nil(t, bucket)
			return nil
		})
	})

	t.Run("cancel rollback-routine on commit", func(t *testing.T) {
		db := createBBoltDB(io.TestDirectory(t))
		bboltTx, _ := db.Begin(true)
		ctx := context.WithValue(context.Background(), struct{}{}, bboltTx)
		store := newBBoltTreeStore(db, "observer bucket", tree.New(tree.NewXor(), testLeafSize))
		tx, _, _ := CreateTestTransaction(1)

		currentRoutines := runtime.NumGoroutine()
		store.dagObserver(ctx, tx, nil)
		assert.Equal(t, tx.Ref(), store.getRoot().(*tree.Xor).Hash())
		_ = bboltTx.Commit()

		test.WaitFor(t, func() (bool, error) {
			return runtime.NumGoroutine() == currentRoutines, nil
		}, 5*time.Second, "timeout while waiting for go routine to exit")
		assert.Equal(t, tx.Ref(), store.getRoot().(*tree.Xor).Hash())

		_ = db.View(func(tx *bbolt.Tx) error {
			bucket := tx.Bucket([]byte("observer bucket"))
			if !assert.NotNil(t, bucket) {
				return nil
			}
			bytes := make([]byte, 4)
			binary.LittleEndian.PutUint32(bytes, 256)
			leaf := bucket.Get(bytes)

			assert.NotNil(t, leaf)
			return nil
		})
	})
}

func TestBboltTree_buildFromDag(t *testing.T) {
	tx0, _, _ := CreateTestTransaction(7)
	tx1a, _, _ := CreateTestTransaction(7, tx0)
	tx1b, _, _ := CreateTestTransaction(7, tx0)
	tx2, _, _ := CreateTestTransaction(7, tx1a, tx1b)
	dag := CreateDAG(t)
	dagState := &state{
		db:    dag.db,
		graph: dag,
	}
	err := dag.Add(context.Background(), tx0, tx1a, tx1b, tx2)
	if !assert.NoError(t, err) {
		return
	}

	t.Run("ok - build tree", func(t *testing.T) {
		store := newBBoltTreeStore(dag.db, "real bucket", tree.New(tree.NewXor(), testLeafSize))

		err := store.migrate(context.Background(), dagState)

		if assert.NoError(t, err) {
			return
		}
		assert.Equal(t, dag.Heads(context.Background())[0], store.getRoot().(*tree.Xor).Hash())
	})

	t.Run("fail - tree is not empty", func(t *testing.T) {
		store := newBBoltTreeStore(dag.db, "fail bucket", tree.New(tree.NewXor(), testLeafSize))
		store.tree.Insert(tx0.Ref(), 0)
		exp := dag.Heads(context.Background())[0]

		err := store.migrate(context.Background(), dagState)

		if assert.NoError(t, err) {
			return
		}
		assert.Equal(t, exp, store.getRoot().(*tree.Xor).Hash())
	})
}
