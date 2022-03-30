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

package tree

import (
	"encoding"
	"fmt"
	"math"
	"sync"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
)

// Data is the interface for data held in each node of the Tree
type Data interface {
	// New creates a new instance, of the same concrete type, initialized to the default/empty state.
	New() Data
	// Clone creates an exact copy using the current instance as a prototype.
	Clone() Data
	// Insert a new transaction reference.
	Insert(ref hash.SHA256Hash) error
	// Delete a transaction reference.
	Delete(ref hash.SHA256Hash) error
	// Add other Data to this one. Returns an error if the underlying datastructures are incompatible.
	Add(other Data) error
	// Subtract other Data from this one. Returns an error if the underlying datastructures are incompatible.
	Subtract(other Data) error
	// IsEmpty returns true if the concrete type is in its default/empty state.
	IsEmpty() bool
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
}

// Tree is the interface for an in-memory tree that provides fast access to Data over requested Lamport Clock ranges.
// Tree is not thread-safe.
type Tree interface {
	// Insert a transaction reference at the specified clock value.
	// The result of inserting the same ref multiple times is undefined.
	Insert(ref hash.SHA256Hash, clock uint32) error
	// Delete a transaction reference without checking if ref is in the Tree
	Delete(ref hash.SHA256Hash, clock uint32) error
	// GetRoot returns the accumulated Data for the entire tree
	GetRoot() Data
	// GetZeroTo returns the LC value closest to the requested clock value together with Data of the same leaf/page.
	// The LC value closest to requested clock is defined as the lowest of:
	// 	- highest LC known to the Tree
	// 	- highest LC of the leaf that clock is on: ceil(clock/leafSize)*leafSize - 1
	GetZeroTo(clock uint32) (Data, uint32)
	// DropLeaves shrinks the tree by dropping all leaves. The parent of a leaf will become the new leaf.
	DropLeaves()
	// GetUpdates return the leaves that have been orphaned or updated since the last call to ResetUpdate.
	// dirty and orphaned are mutually exclusive.
	GetUpdates() (dirty map[uint32][]byte, orphaned []uint32, err error)
	// ResetUpdate forgets all currently tracked changes.
	ResetUpdate()
	// Load builds a tree from binary leaf data. The keys in leaves correspond to a node's split value.
	Load(leaves map[uint32][]byte) error
}

/*
tree creates a binary tree, where the leaves contain Data over a fixed range (one page) of Lamport Clock values.
	- The Data of the parent node is the sum of that of its children. Thus root contains the sum of all Data in the tree.
	- The value that splits a node into its children is used as a nodeID since it is unique, even after tree resizing.
	- Since the leaves are of fixed size, a new root is created when added something to a clock outside the current root range.
	- Whenever a new branch is created, a string of left Nodes is created all the way down to the leaf.
	- tree is not thread-safe. Since the tree is agnostic to its content, great care must be taken to prevent adding the same data more than once.
*/
type tree struct {
	treeSize uint32
	leafSize uint32
	root     *node
	// storage
	prototype      Data
	dirtyLeaves    map[uint32]*node
	orphanedLeaves map[uint32]struct{}
	mutex          sync.Mutex
}

// New creates a new tree with the given leafSize and of the same type of Data as the prototype.
// leafSize should be an even number.
func New(prototype Data, leafSize uint32) Tree {
	tr := &tree{prototype: prototype.New()}
	tr.resetDefaults(leafSize)
	return tr
}

func (t *tree) resetDefaults(leafSize uint32) {
	t.root = newNode(leafSize/2, leafSize, t.prototype.New())
	t.leafSize = leafSize
	t.treeSize = leafSize
	t.dirtyLeaves = map[uint32]*node{t.root.splitLC: t.root}
	t.orphanedLeaves = nil
}

func (t *tree) Load(leaves map[uint32][]byte) error {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	// initialize tree
	split := uint32(math.MaxUint32)
	for k := range leaves {
		if k < split {
			split = k
		}
	}
	t.resetDefaults(2 * split)

	// build tree
	// note: current implementation requires a maximum of d*2^d calls to Data.Add(), where d is tree depth. Building the tree bottom up would require a max of 2^(d-1) calls.
	var err error
	var leaf []byte
	for split, leaf = range leaves {
		data := t.prototype.New()
		err = data.UnmarshalBinary(leaf)
		if err != nil {
			return err
		}
		err = t.updateOrCreatePath(split, func(n *node) error {
			return n.data.Add(data)
		})
		if err != nil {
			return err
		}
	}

	t.resetUpdate()

	return nil
}

func (t *tree) Insert(ref hash.SHA256Hash, clock uint32) error {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	return t.updateOrCreatePath(clock, func(n *node) error {
		return n.data.Insert(ref)
	})
}

func (t *tree) Delete(ref hash.SHA256Hash, clock uint32) error {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	return t.updateOrCreatePath(clock, func(n *node) error {
		return n.data.Delete(ref)
	})
}

// updateOrCreatePath calls fn on all nodes on the path from the root to leaf containing the clock value.
// If the path/leaf does not exist it will be created.
// The leaf is marked dirty.
func (t *tree) updateOrCreatePath(clock uint32, fn func(n *node) error) error {
	// grow tree if needed
	for clock >= t.treeSize {
		t.reRoot()
	}

	// apply fn to all nodes on path
	var current *node
	next := t.root
	for next != nil {
		current = next
		err := fn(current)
		if err != nil {
			return fmt.Errorf("failed for node with splitLC %d: %w", next.splitLC, err)
		}
		next = t.getNextNode(current, clock)
	}
	t.dirtyLeaves[current.splitLC] = current

	return nil
}

func (t *tree) newBranch(start, stop uint32) *node {
	split := (stop + start) / 2
	n := newNode(split, stop, t.prototype.New())
	if stop-start > t.leafSize {
		n.left = t.newBranch(start, split)
	} else {
		t.dirtyLeaves[n.splitLC] = n
	}
	return n
}

// reRoot creates a new root with Data from the current root and adds current root as its left branch.
func (t *tree) reRoot() {
	newRoot := newNode(t.treeSize, 2*t.treeSize, t.root.data.Clone())
	newRoot.left = t.root
	t.root = newRoot
	t.treeSize *= 2
}

// getNextNode retrieves the next node based on the clock value. If the node does not exist it is created.
func (t *tree) getNextNode(n *node, clock uint32) *node {
	// return nil if n is a leaf
	if n.isLeaf() {
		return nil
	}

	if clock < n.splitLC {
		return n.left
	}

	if n.right == nil {
		n.right = t.newBranch(n.splitLC, n.limitLC)
	}
	return n.right
}

func (t *tree) GetRoot() Data {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	return t.root.data.Clone()
}

func (t *tree) GetZeroTo(clock uint32) (Data, uint32) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	data := t.root.data.Clone()
	next := t.root
	for {
		current := next
		if clock < current.splitLC {
			if current.right != nil {
				// Only fails when Data structures do not match, which should not happen for Data managed by the tree.
				_ = data.Subtract(current.right.data)
			}
			next = current.left
		} else {
			next = current.right
		}
		if next == nil {
			return data, rightmostLeafClock(current)
		}
	}
}

// rightmostLeafClock finds the rightmost leaf of the given node and returns its maximum clock value.
func rightmostLeafClock(n *node) uint32 {
	for {
		if n.right != nil {
			n = n.right
		} else if n.left != nil {
			n = n.left
		} else {
			return n.limitLC - 1
		}
	}
}

func (t tree) GetUpdates() (dirty map[uint32][]byte, orphaned []uint32, err error) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	dirty = make(map[uint32][]byte, len(t.dirtyLeaves))
	for k, v := range t.dirtyLeaves {
		b, err := v.data.MarshalBinary()
		if err != nil {
			return nil, nil, err
		}
		dirty[k] = b
	}
	for k := range t.orphanedLeaves {
		orphaned = append(orphaned, k)
	}
	return dirty, orphaned, nil
}

func (t *tree) ResetUpdate() {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	t.resetUpdate()
}

func (t *tree) resetUpdate() {
	t.dirtyLeaves = map[uint32]*node{}
	t.orphanedLeaves = nil
}

type dropLeavesUpdate struct {
	dirty    map[uint32]*node
	orphaned map[uint32]struct{}
}

func (t *tree) DropLeaves() {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	// don't drop root
	if t.root == nil || t.root.isLeaf() {
		return
	}

	update := &dropLeavesUpdate{
		dirty:    map[uint32]*node{},
		orphaned: map[uint32]struct{}{},
	}
	dropLeavesR(t.root, update)

	t.dirtyLeaves = update.dirty
	if t.orphanedLeaves == nil {
		t.orphanedLeaves = update.orphaned
	} else {
		for k := range update.orphaned {
			t.orphanedLeaves[k] = struct{}{}
		}
	}
	t.leafSize *= 2
}

func dropLeavesR(n *node, update *dropLeavesUpdate) {
	if n == nil {
		// n = parent.right might not exist
		return
	}
	// if n.left is a leaf, make n node a leaf
	if n.left.isLeaf() {
		update.dirty[n.splitLC] = n
		update.orphaned[n.left.splitLC] = struct{}{}
		if n.right != nil {
			update.orphaned[n.right.splitLC] = struct{}{}
		}
		n.left = nil
		n.right = nil
		return
	}
	dropLeavesR(n.left, update)
	dropLeavesR(n.right, update)
}

// node
type node struct {
	// splitLC point for left / right node. splitLC is part of the right node.
	splitLC uint32
	// limitLC is the node's upper limit for the LC (exclusive)
	limitLC uint32
	// data held by the node. Should not be nil
	data Data

	// child nodes. if left == nil, current node is a leaf
	left  *node
	right *node
}

func newNode(splitLC, limitLC uint32, data Data) *node {
	return &node{
		splitLC: splitLC,
		limitLC: limitLC,
		data:    data,
	}
}

func (n node) isLeaf() bool {
	return n.left == nil
}
