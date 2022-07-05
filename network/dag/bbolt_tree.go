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
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/nuts-node/network/dag/tree"
	"github.com/nuts-foundation/nuts-node/network/log"
)

type treeStore struct {
	bucketName string
	tree       tree.Tree
}

// newTreeStore returns an instance of a BBolt based tree store. Buckets managed by this store are filled to treeBucketFillPercent
func newTreeStore(bucketName string, tree tree.Tree) *treeStore {
	return &treeStore{
		bucketName: bucketName,
		tree:       tree,
	}
}

// getRoot returns the tree.Data summary of the entire tree.
func (store *treeStore) getRoot() tree.Data {
	return store.tree.GetRoot()
}

// getZeroTo returns the tree.Data sum of all tree pages/leaves upto and including the one containing the requested Lamport Clock value.
// In addition to the data, the highest LC value of this range is returned.
func (store *treeStore) getZeroTo(clock uint32) (tree.Data, uint32) {
	return store.tree.GetZeroTo(clock)
}

func (store *treeStore) isEmpty() bool {
	return store.tree.GetRoot().IsEmpty()
}

// write inserts a transaction reference to the in-memory tree and to persistent storage.
// The tree is not aware of previously seen transactions, so it should be transactional with updates to the dag.
func (store *treeStore) write(tx stoabs.WriteTx, transaction Transaction) error {
	if transaction != nil { // can happen when payload is written for private TX
		dirty := store.tree.InsertGetDirty(transaction.Ref(), transaction.Clock())
		return store.writeUpdates(tx, dirty, nil)
	}
	return nil
}

// read fills the tree with data in the bucket.
// Returns an error the bucket does not exist, or if data in the bucket doesn't match the tree's Data prototype.
func (store *treeStore) read(tx stoabs.ReadTx) error {
	reader, err := tx.GetShelfReader(store.bucketName)
	if err != nil {
		return err
	}
	if reader == nil {
		log.Logger().Warnf("tree bucket '%s' does not exist", store.bucketName)
		return nil
	}

	// get data
	rawData := map[uint32][]byte{}
	err = reader.Iterate(func(k stoabs.Key, v []byte) error {
		rawData[keyToClock(k)] = v
		return nil
	})
	if err != nil {
		return err
	}

	// nothing to load
	if len(rawData) == 0 {
		return nil
	}

	// build tree
	return store.tree.Load(rawData)
}

// writeUpdates writes an incremental update to the bucket.
// The incremental update is defined as changes to the tree since the last call to Tree.ResetUpdate,
// which is called when writeUpdates completes successfully.
func (store *treeStore) writeUpdates(tx stoabs.WriteTx, dirties map[uint32][]byte, orphaned []uint32) error {
	writer, err := tx.GetShelfWriter(store.bucketName)
	// writer should never be nil
	if err != nil {
		return err
	}

	// delete orphaned leaves
	for _, orphan := range orphaned {
		err = writer.Delete(clockToKey(orphan))
		if err != nil {
			return err
		}
	}

	// write new/updated leaves
	for dirty, data := range dirties {
		err = writer.Put(clockToKey(dirty), data)
		if err != nil {
			return err
		}
	}
	return nil
}

func clockToKey(clock uint32) stoabs.Key {
	var bytes [4]byte
	binary.LittleEndian.PutUint32(bytes[:], clock)
	return stoabs.BytesKey(bytes[:])
}

func keyToClock(key stoabs.Key) uint32 {
	return binary.LittleEndian.Uint32(key.Bytes())
}
