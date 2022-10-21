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
	"encoding/binary"
	"errors"
	"sync"

	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/nuts-node/network/dag/tree"
)

type treeStore struct {
	shelf string
	tree  tree.Tree
	mutex sync.Mutex
}

// newTreeStore returns an instance of a tree store.
func newTreeStore(shelfName string, tree tree.Tree) *treeStore {
	return &treeStore{
		shelf: shelfName,
		tree:  tree,
	}
}

// getRoot returns the tree.Data summary of the entire tree.
func (store *treeStore) getRoot() tree.Data {
	store.mutex.Lock()
	defer store.mutex.Unlock()

	return store.tree.GetRoot()
}

// getZeroTo returns the tree.Data sum of all tree pages/leaves upto and including the one containing the requested Lamport Clock value.
// In addition to the data, the highest LC value of this range is returned.
func (store *treeStore) getZeroTo(clock uint32) (tree.Data, uint32) {
	store.mutex.Lock()
	defer store.mutex.Unlock()

	return store.tree.GetZeroTo(clock)
}

// write inserts a transaction reference to the in-memory tree and to persistent storage.
// The tree is not aware of previously seen transactions, so it should be transactional with updates to the dag.
func (store *treeStore) write(tx stoabs.WriteTx, transaction Transaction) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()

	writer, err := tx.GetShelfWriter(store.shelf)
	if err != nil {
		return err
	}

	store.tree.Insert(transaction.Ref(), transaction.Clock())
	dirties, orphaned := store.tree.GetUpdates()
	store.tree.ResetUpdates() // failure after this point results in rollback anyway

	// delete orphaned leaves
	for _, orphan := range orphaned { // always zero
		err = writer.Delete(clockToKey(orphan))
		if err != nil {
			return err
		}
	}

	// write new/updated leaves
	for dirty, data := range dirties { // contains exactly 1 dirty
		err = writer.Put(clockToKey(dirty), data)
		if err != nil {
			return err
		}
	}
	return nil
}

// read fills the tree with data in the shelf.
// Returns an error if data in the shelf doesn't match the tree's Data prototype.
// Does not alter the tree if the shelf does not exist.
func (store *treeStore) read(tx stoabs.ReadTx) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()

	// get data
	rawData, err := readRaw(tx, store.shelf)
	if err != nil {
		return err
	}

	// build tree
	return store.tree.Load(rawData) // does nothing if len(rawData) == 0, when the shelf does not exist for instance.
}

func readRaw(tx stoabs.ReadTx, shelf string) (map[uint32][]byte, error) {
	rawData := map[uint32][]byte{}
	err := tx.GetShelfReader(shelf).Iterate(func(k stoabs.Key, v []byte) error {
		rawData[keyToClock(k)] = v
		return nil
	}, clockToKey(0))
	if err != nil {
		return nil, err
	}
	return rawData, nil
}

func (store *treeStore) rebuildPage(tx stoabs.WriteTx, clock uint32, dagData tree.Data) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()

	treeData := store.tree.Prototype()
	if treeData == nil {
		return errors.New("tree has no Data prototype")
	}

	// read treeData
	leafID := clockToPage(clock)
	writer, err := tx.GetShelfWriter(store.shelf)
	treeBytes, err := writer.Get(clockToKey(leafID))
	if err != nil {
		return err
	}

	// compare dag with tree
	dagBytes, err := dagData.MarshalBinary()
	if !bytes.Equal(dagBytes, treeBytes) {
		// page needs to be corrected
		// TODO: add logging
		// write page
		if err = writer.Put(clockToKey(leafID), dagBytes); err != nil {
			return err
		}

		// must reload tree within the context of the mutex lock to guarantee db/mem are in sync
		rawData, err := readRaw(tx, store.shelf)
		if err != nil {
			return err
		}
		// new page is not committed yet
		rawData[leafID] = dagBytes
		return store.tree.Load(rawData)
	}
	return nil
}

func clockToPage(clock uint32) uint32 {
	return (clock/PageSize)*PageSize + PageSize/2
}

func clockToKey(clock uint32) stoabs.Key {
	var bytes [4]byte
	binary.LittleEndian.PutUint32(bytes[:], clock)
	return stoabs.BytesKey(bytes[:])
}

func keyToClock(key stoabs.Key) uint32 {
	return binary.LittleEndian.Uint32(key.Bytes())
}

type PageNotFoundError struct {
	Err error
}

func (e PageNotFoundError) Error() string {
	return e.Err.Error()
}

func (e PageNotFoundError) Unwrap() error {
	return e.Err
}
