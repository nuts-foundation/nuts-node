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
	"sync"

	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/nuts-node/network/dag/tree"
)

type treeStore struct {
	bucketName string
	tree       tree.Tree
	mutex      sync.Mutex
}

// newTreeStore returns an instance of a tree store.
func newTreeStore(bucketName string, tree tree.Tree) *treeStore {
	return &treeStore{
		bucketName: bucketName,
		tree:       tree,
	}
}

// getRoot returns the tree.Data summary of the entire tree.
func (store *treeStore) getRoot() tree.Data {
	store.mutex.Lock()
	defer store.mutex.Unlock()

	return store.tree.Root()
}

// getZeroTo returns the tree.Data sum of all tree pages/leaves upto and including the one containing the requested Lamport Clock value.
// In addition to the data, the highest LC value of this range is returned.
func (store *treeStore) getZeroTo(clock uint32) (tree.Data, uint32) {
	store.mutex.Lock()
	defer store.mutex.Unlock()

	return store.tree.ZeroTo(clock)
}

// write inserts a transaction reference to the in-memory tree and to persistent storage.
// The tree is not aware of previously seen transactions, so it should be transactional with updates to the dag.
func (store *treeStore) write(tx stoabs.WriteTx, transaction Transaction) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()

	store.tree.Insert(transaction.Ref(), transaction.Clock())
	return store.writeWithoutLock(tx)
}

// writeWithoutLock writes all current changes in the treeStore to disk.
// It is the callers responsibility to prevent race conditions on treeStore. Use treeStore.mutex if needed.
func (store *treeStore) writeWithoutLock(tx stoabs.WriteTx) error {
	dirties, orphaned := store.tree.Updates()
	store.tree.ResetUpdates() // failure after this point results in rollback anyway

	writer := tx.GetShelfWriter(store.bucketName)

	// delete orphaned leaves
	for _, orphan := range orphaned { // always zero
		err := writer.Delete(clockToKey(orphan))
		if err != nil {
			return err
		}
	}

	// write new/updated leaves
	for dirty, data := range dirties { // contains exactly 1 dirty
		err := writer.Put(clockToKey(dirty), data)
		if err != nil {
			return err
		}
	}
	return nil
}

// read fills the tree with data in the bucket.
// Returns an error the bucket does not exist, or if data in the bucket doesn't match the tree's Data prototype.
func (store *treeStore) read(tx stoabs.ReadTx) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()

	reader := tx.GetShelfReader(store.bucketName)

	// get data
	rawData := map[uint32][]byte{}
	err := reader.Iterate(func(k stoabs.Key, v []byte) error {
		rawData[keyToClock(k)] = v
		return nil
	}, clockToKey(0))
	if err != nil {
		return err
	}

	// build tree
	return store.tree.Load(rawData)
}

func clockToKey(clock uint32) stoabs.Key {
	var bytes [4]byte
	binary.LittleEndian.PutUint32(bytes[:], clock)
	return stoabs.BytesKey(bytes[:])
}

func keyToClock(key stoabs.Key) uint32 {
	return binary.LittleEndian.Uint32(key.Bytes())
}
