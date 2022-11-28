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
	"encoding/gob"
	"fmt"
	"io"
	"sync"

	"github.com/nuts-foundation/nuts-node/network/dag/tree"
)

type treeStore struct {
	perClock map[uint32][]byte
	tree     tree.Tree
	mutex    sync.Mutex
}

// newTreeStore returns an instance of a tree store.
func newTreeStore(tree tree.Tree) *treeStore {
	store := treeStore{
		perClock: make(map[uint32][]byte),
		tree:     tree,
	}
	gob.Register(store.perClock)
	return &store
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

func (store *treeStore) insert(transaction Transaction) {
	store.tree.Insert(transaction.Ref(), transaction.Clock())

	dirties, orphaned := store.tree.Updates()
	store.tree.ResetUpdates()

	// delete orphaned leaves
	for _, clock := range orphaned { // always zero
		delete(store.perClock, clock)
	}

	// write new/updated leaves
	for clock, data := range dirties { // contains exactly 1 dirty
		store.perClock[clock] = data
	}
}

// ReadFrom implements nutstx.Aggregate.
func (store *treeStore) ReadFrom(r io.Reader) error {
	// full reset
	for key := range store.perClock {
		delete(store.perClock, key)
	}

	// unmarshal dump
	err := gob.NewDecoder(r).Decode(&store.perClock)
	if err != nil {
		return fmt.Errorf("tree dump: %w", err)
	}

	// build tree
	return store.tree.Load(store.perClock)
}

// WriteTo implements nutstx.Aggregate.
func (store *treeStore) WriteTo(w io.Writer) error {
	return gob.NewEncoder(w).Encode(store.perClock)
}
