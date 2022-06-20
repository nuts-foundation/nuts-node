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
	"encoding/binary"
	"time"

	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/nuts-node/network/dag/tree"
	"github.com/nuts-foundation/nuts-node/network/log"
)

const (
	// treeBucketFillPercent can be much higher than default 0.5 since the keys (unique node ids)
	// should be added to the bucket in monotonic increasing order, and the values are of fixed size.
	treeBucketFillPercent = 0.9
	// defaultObserverRollbackTimeOut is the default time waited before triggering a rollback of a transaction.
	defaultObserverRollbackTimeOut = 10 * time.Second
)

// observerRollbackTimeOut is the time waited before triggering a rollback of a transaction.
// timeout must not be shorter than expected write operation to disk.
var observerRollbackTimeOut = defaultObserverRollbackTimeOut

type bboltTree struct {
	db                     stoabs.KVStore
	bucketFillPercent      float64
	bucketName             string
	tree                   tree.Tree
	activeRollbackRoutines *uint32
	numRollbacks           *uint32
}

// newBBoltTreeStore returns an instance of a BBolt based tree store. Buckets managed by this store are filled to treeBucketFillPercent
func newBBoltTreeStore(db stoabs.KVStore, bucketName string, tree tree.Tree) *bboltTree {
	return &bboltTree{
		db:                     db,
		bucketFillPercent:      treeBucketFillPercent,
		bucketName:             bucketName,
		tree:                   tree,
		activeRollbackRoutines: new(uint32),
		numRollbacks:           new(uint32),
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
func (store *bboltTree) dagObserver(tx stoabs.WriteTx, transaction Transaction) error {
	dirty := store.tree.InsertGetDirty(transaction.Ref(), transaction.Clock())
	store.tree.ResetUpdate()

	return store.writeUpdates(tx, dirty, nil)
}

// read fills the tree with data in the bucket.
// Returns an error the bucket does not exist, or if data in the bucket doesn't match the tree's Data prototype.
func (store *bboltTree) read(tx stoabs.ReadTx) error {
	// get bucket
	reader, _ := tx.GetShelfReader(store.bucketName)
	if reader == nil {
		// should only happen once for a new tree/bucket.
		log.Logger().Warnf("tree bucket '%s' does not exist", store.bucketName)
		return nil
	}

	// get data
	rawData := map[uint32][]byte{}
	_ = reader.Iterate(func(k stoabs.Key, v []byte) error {
		split := binary.LittleEndian.Uint32(k.Bytes())
		rawData[split] = v
		return nil
	})

	// build tree
	return store.tree.Load(rawData)
}

// writeUpdates writes an incremental update to the bucket.
// The incremental update is defined as changes to the tree since the last call to Tree.ResetUpdate,
// which is called when writeUpdates completes successfully.
func (store *bboltTree) writeUpdates(tx stoabs.WriteTx, dirties map[uint32][]byte, orphaned []uint32) error {
	writer, err := tx.GetShelfWriter(store.bucketName)
	if err != nil {
		return err
	}

	// delete orphaned leaves
	key := make([]byte, 4)
	for _, orphan := range orphaned {
		binary.LittleEndian.PutUint32(key, orphan)
		err = writer.Delete(stoabs.BytesKey(key))
		if err != nil {
			return err
		}
	}

	// write new/updated leaves
	for dirty, data := range dirties {
		binary.LittleEndian.PutUint32(key, dirty)
		err = writer.Put(stoabs.BytesKey(key), data)
		if err != nil {
			return err
		}
	}
	return nil
}
