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
	"fmt"
	"go.etcd.io/bbolt"
	"time"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag/tree"
	"github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/network/storage"
)

// treeBucketFillPercent can be much higher than default 0.5 since the keys (unique node ids)
// should be added to the bucket in monotonic increasing order, and the values are of fixed size.
const treeBucketFillPercent = 0.9

type bboltTree struct {
	db                *bbolt.DB
	bucketFillPercent float64
	bucketName        string
	tree              tree.Tree
}

// newBBoltTreeStore returns an instance of a BBolt based tree store. Buckets managed by this store are filled to treeBucketFillPercent
func newBBoltTreeStore(db *bbolt.DB, bucketName string, tree tree.Tree) *bboltTree {
	return &bboltTree{
		db:                db,
		bucketFillPercent: treeBucketFillPercent,
		bucketName:        bucketName,
		tree:              tree,
	}
}

// getRoot returns the tree.Data summary of the entire tree.
func (store *bboltTree) getRoot() tree.Data {
	return store.tree.GetRoot()
}

// getZeroTo returns the tree.Data sum of all tree pages/leaves upto and including the one containing the requested Lamport Clock value.
// In addition to the data, the highest LC value of this range is returned.
func (store *bboltTree) getZeroTo(clock uint32) (tree.Data, uint32) {
	return store.tree.GetZeroTo(clock)
}

func (store *bboltTree) isEmpty() bool {
	return store.tree.GetRoot().IsEmpty()
}

// dagCallback inserts a transaction reference to the in-memory tree and to persistent storage.
// The tree is not aware of previously seen transactions, so it should be transactional with updates to the dag.
func (store *bboltTree) dagObserver(ctx context.Context, transaction Transaction, _ []byte) {
	if transaction != nil { // can happen when payload is written for private TX
		err := storage.BBoltTXUpdate(ctx, store.db, func(callbackCtx context.Context, tx *bbolt.Tx) error {
			err := store.tree.Insert(transaction.Ref(), transaction.Clock())
			if err != nil {
				return err
			}

			// Rollback after timeout to bring tree and DAG back in sync.
			// A call to writeUpdates will persist all uncommitted tree changes. So a failed bboltTx will be dropped by the dag and (eventually) persisted by the tree.
			c, cancel := context.WithTimeout(context.Background(), 10*time.Second) // << timeout must not be shorter than expected write operation to disk
			go func() {
				<-c.Done()
				err := c.Err()
				if err == context.DeadlineExceeded {
					log.Logger().Warnf("deadline exceeded - rollback transaction %s from %s", transaction.Ref(), store.bucketName)
					if err := store.tree.Delete(transaction.Ref(), transaction.Clock()); err != nil {
						log.Logger().Errorf("rollback of transaction %s failed - %s is not in sync with DAG", transaction.Ref(), store.bucketName)
					}
				}
			}()
			tx.OnCommit(func() {
				cancel()
			})

			return store.writeUpdates(callbackCtx)
		})
		if err != nil {
			log.Logger().Errorf("failed to add transaction to %s: %s", store.bucketName, err.Error())
		}
	}
}

// buildFromDag builds a tree by walking over the dag and adding all Transaction references to the tree without checking for validity.
// The tree is stored on disk once it is in sync with the dag.
// Should only be called on an empty tree.
func (store *bboltTree) buildFromDag(ctx context.Context, state State) error {
	if !store.isEmpty() {
		return fmt.Errorf("failed to build tree on %s - tree is not empty", store.bucketName)
	}

	err := state.Walk(ctx, func(_ context.Context, transaction Transaction) bool {
		err := store.tree.Insert(transaction.Ref(), transaction.Clock())
		return err != nil
	}, hash.EmptyHash())
	if err != nil {
		return err
	}

	err = store.writeUpdates(ctx)
	if err != nil {
		return err
	}

	return nil
}

// read fills the tree with data in the bucket.
// Returns an error the bucket does not exist, or if data in the bucket doesn't match the tree's Data prototype.
func (store *bboltTree) read(ctx context.Context) error {
	return storage.BBoltTXUpdate(ctx, store.db, func(_ context.Context, tx *bbolt.Tx) error {
		// get bucket
		bucket := tx.Bucket([]byte(store.bucketName))
		if bucket == nil {
			// should only happen once for a new tree/bucket.
			log.Logger().Warnf("tree bucket '%s' does not exist", store.bucketName)
			return nil
		}

		// get data
		rawData := map[uint32][]byte{}
		_ = bucket.ForEach(func(k, v []byte) error {
			split := binary.LittleEndian.Uint32(k)
			rawData[split] = v
			return nil
		})

		// build tree
		return store.tree.Load(rawData)
	})
}

// writeUpdates writes an incremental update to the bucket.
// The incremental update is defined as changes to the tree since the last call to Tree.ResetUpdate,
// which is called when writeUpdates completes successfully.
func (store *bboltTree) writeUpdates(ctx context.Context) error {
	return storage.BBoltTXUpdate(ctx, store.db, func(_ context.Context, tx *bbolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte(store.bucketName))
		if err != nil {
			return err
		}
		bucket.FillPercent = store.bucketFillPercent

		// get data
		dirties, orphaned, err := store.tree.GetUpdates()
		if err != nil {
			return err
		}
		tx.OnCommit(store.tree.ResetUpdate)

		// delete orphaned leaves
		key := make([]byte, 4)
		for _, orphan := range orphaned {
			binary.LittleEndian.PutUint32(key, orphan)
			err = bucket.Delete(key)
			if err != nil {
				return err
			}
		}

		// write new/updated leaves
		for dirty, data := range dirties {
			binary.LittleEndian.PutUint32(key, dirty)
			err = bucket.Put(key, data)
			if err != nil {
				return err
			}
		}
		return nil
	})
}
