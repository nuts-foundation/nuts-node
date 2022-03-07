package tree

import (
	"encoding"
	"encoding/json"
	"fmt"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"math"
)

// Data is the interface for data held in each node of the Tree
type Data interface {
	// New creates a copy of this instance that is initialized to the default/empty state.
	New() Data
	// Clone creates an exact copy using the current instance as a prototype.
	Clone() Data
	// Insert a new transaction reference.
	Insert(ref hash.SHA256Hash) error
	// Add other Data to this one. Returns an error if the underlying datastructures are incompatible.
	Add(other Data) error
	// Subtract other Data from this one. Returns an error if the underlying datastructures are incompatible.
	Subtract(other Data) error
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
}

type Tree interface {
	// Insert a transaction reference at the specified clock value. The result of inserting the same ref multiple times is undefined.
	Insert(ref hash.SHA256Hash, clock uint32) error
	// GetRoot returns the accumulated Data for the entire tree
	GetRoot() Data
	// GetZeroTo returns the LC value closest to the requested clock value together with Data of the same range.
	// The LC value closest to requested clock is defined as the lowest of:
	// 	- highest LC known to the Tree
	// 	- highest LC of the leaf that clock is on: ceil(clock/leafSize)*leafSize - 1
	GetZeroTo(clock uint32) (Data, uint32)
	// DropLeaves shrinks the tree by dropping all leaves. The parent of a leaf will become the new leaf.
	DropLeaves()
	// GetUpdate return the leaves that have been orphaned or updated since the last call to ResetUpdate.
	// dirty and orphaned are mutually exclusive.
	GetUpdate() (dirty map[uint32][]byte, orphaned []uint32, err error)
	// ResetUpdate forgets all currently tracked changes.
	ResetUpdate()
	// Load builds a tree from binary leaf data. The keys in leaves correspond to a node's split value.
	Load(leaves map[uint32][]byte) error
}

/*
tree creates a binary tree, where the leaves contain Data over a fixed range of Lamport Clock (uint32) values.
	- The Data of the parent node is the sum of that of its children. Thus root contains the sum of all Data in the tree.
	- The value that splits a node into its children is used as a nodeID since it is unique, even after tree resizing.
	- Since the leaves are of fixed size, a new root is created when added something to a clock outside the current root range.
	- Whenever a new branch is created, a string of left Nodes is created all the way down to the leaf.
	- tree is not thread-safe. Since the tree is agnostic to its content, great care must be taken to prevent adding the same data more than once.
*/
type tree struct {
	Depth    int    `json:"depth"`
	MaxSize  uint32 `json:"max_size"`
	LeafSize uint32 `json:"leaf_size"`
	Root     *node  `json:"root"`
	// storage
	prototype      Data
	dirtyLeaves    map[uint32]*node
	orphanedLeaves map[uint32]struct{}
}

// New creates a new tree with the given leafSize and of the same type of Data as the prototype.
func New(prototype Data, leafSize uint32) *tree {
	tr := &tree{prototype: prototype.New()}
	tr.resetDefaults(leafSize)
	return tr
}

func (t *tree) resetDefaults(leafSize uint32) {
	t.Root = newNode(leafSize/2, leafSize, t.prototype.New())
	t.LeafSize = leafSize
	t.MaxSize = leafSize
	t.Depth = 0
	t.dirtyLeaves = map[uint32]*node{t.Root.SplitLC: t.Root}
	t.orphanedLeaves = nil
}

func (t *tree) Load(leaves map[uint32][]byte) error {
	// initialize tree
	split := uint32(math.MaxUint32)
	for k := range leaves {
		if k < split {
			split = k
		}
	}
	t.resetDefaults(2 * split)

	// build tree
	// note: current implementation requires a maximum of d*2^d calls to Data.Add(), where d = t.Depth. Building the tree bottom up would require a max of 2^(d-1) calls.
	var err error
	var leaf []byte
	for split, leaf = range leaves {
		data := t.prototype.New()
		err = data.UnmarshalBinary(leaf)
		if err != nil {
			return err
		}
		err = t.applyToPath(split, func(n *node) error {
			return n.Data.Add(data)
		})
		if err != nil {
			return err
		}
	}

	// TODO: should leaves be dirty or not?
	t.ResetUpdate()

	return nil
}

func (t *tree) Insert(ref hash.SHA256Hash, clock uint32) error {
	return t.applyToPath(clock, func(n *node) error {
		return n.Data.Insert(ref)
	})
}

// applyToPath calls fn on all nodes on the path from the root to leaf containing the clock value.
// If the path/leaf does not exist it will be created.
func (t *tree) applyToPath(clock uint32, fn func(n *node) error) error {
	// grow tree if needed
	for clock >= t.MaxSize {
		t.reRoot()
	}

	// apply fn to all nodes on path
	var current *node
	next := t.Root
	for next != nil {
		current = next
		err := fn(current)
		if err != nil {
			return fmt.Errorf("failed for node with splitLC %d: %w", next.SplitLC, err)
		}
		next = t.getNextNode(current, clock)
	}
	t.dirtyLeaves[current.SplitLC] = current

	return nil
}

func (t *tree) newBranch(start, stop uint32) *node {
	split := (stop + start) / 2
	n := newNode(split, stop, t.prototype.New())
	if stop-start > t.LeafSize {
		n.Left = t.newBranch(start, split)
	} else {
		t.dirtyLeaves[n.SplitLC] = n
	}
	return n
}

// reRoot creates a new Root with Data from the current Root and adds current Root as its Left branch.
func (t *tree) reRoot() {
	newRoot := newNode(t.MaxSize, 2*t.MaxSize, t.Root.Data.Clone())
	newRoot.Left = t.Root
	t.Root = newRoot
	t.MaxSize *= 2
	t.Depth++
}

// getNextNode retrieves the next node based on the clock value. If the node does not exist it is created.
func (t *tree) getNextNode(n *node, clock uint32) *node {
	// return nil if n is a leaf
	if n.isLeaf() {
		return nil
	}

	if clock < n.SplitLC {
		return n.Left
	} else {
		if n.Right == nil {
			n.Right = t.newBranch(n.SplitLC, n.LimitLC)
		}
		return n.Right
	}
}

func (t *tree) GetRoot() Data {
	return t.Root.Data.Clone()
}

func (t *tree) GetZeroTo(clock uint32) (Data, uint32) {
	data := t.Root.Data.Clone()
	next := t.Root
	for {
		current := next
		if clock < current.SplitLC {
			if current.Right != nil {
				// Only fails when Data structures do not match, which should not happen for Data managed by the tree.
				_ = data.Subtract(current.Right.Data)
			}
			next = current.Left
		} else {
			next = current.Right
		}
		if next == nil {
			return data, rightmostLeafClock(current)
		}
	}
}

// rightmostLeafClock finds the rightmost leaf of the given node and returns its maximum clock value.
func rightmostLeafClock(n *node) uint32 {
	for {
		if n.Right != nil {
			n = n.Right
		} else if n.Left != nil {
			n = n.Left
		} else {
			return n.LimitLC - 1
		}
	}
}

func (t tree) GetUpdate() (dirty map[uint32][]byte, orphaned []uint32, err error) {
	dirty = make(map[uint32][]byte, len(t.dirtyLeaves))
	for k, v := range t.dirtyLeaves {
		b, err := v.Data.MarshalBinary()
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
	t.dirtyLeaves = map[uint32]*node{}
	t.orphanedLeaves = nil
}

type dropLeavesUpdate struct {
	dirty    map[uint32]*node
	orphaned map[uint32]struct{}
}

func (t *tree) DropLeaves() {
	// don't drop root
	if t.Root == nil || t.Root.isLeaf() {
		return
	}

	update := &dropLeavesUpdate{
		dirty:    map[uint32]*node{},
		orphaned: map[uint32]struct{}{},
	}
	dropLeaves(t.Root, update)

	t.dirtyLeaves = update.dirty
	if t.orphanedLeaves == nil {
		t.orphanedLeaves = update.orphaned
	} else {
		for k := range update.orphaned {
			t.orphanedLeaves[k] = struct{}{}
		}
	}
	t.LeafSize *= 2
	t.Depth--
}

func dropLeaves(n *node, update *dropLeavesUpdate) {
	if n == nil {
		// n = parent.Right might not exist
		return
	}
	// if n.Left is a leaf, make n node a leaf
	if n.Left.isLeaf() {
		update.dirty[n.SplitLC] = n
		update.orphaned[n.Left.SplitLC] = struct{}{}
		if n.Right != nil {
			update.orphaned[n.Right.SplitLC] = struct{}{}
		}
		n.Left = nil
		n.Right = nil
		return
	}
	dropLeaves(n.Left, update)
	dropLeaves(n.Right, update)
}

// node
type node struct {
	// SplitLC point for Left / Right node. SplitLC is part of the right node.
	SplitLC uint32 `json:"split"`
	// LimitLC is the node's upper limit for the LC (exclusive)
	LimitLC uint32 `json:"limit"`
	// Data held by the node. Should not be nil
	Data Data `json:"data"`

	// child nodes. if Left == nil, current node is a leaf
	Left  *node `json:"left,omitempty"`
	Right *node `json:"right,omitempty"`
}

func newNode(splitLC, limitLC uint32, data Data) *node {
	return &node{
		SplitLC: splitLC,
		LimitLC: limitLC,
		Data:    data,
	}
}

func (n node) isLeaf() bool {
	return n.Left == nil
}

func (n *node) UnmarshalJSON(bytes []byte) error {

	tmpNode := struct {
		SplitLC uint32                 `json:"split"`
		LimitLC uint32                 `json:"limit"`
		Left    *node                  `json:"left,omitempty"`
		Right   *node                  `json:"right,omitempty"`
		Data    map[string]interface{} `json:"data"`
	}{}
	err := json.Unmarshal(bytes, &tmpNode)
	if err != nil {
		return err
	}
	n.SplitLC = tmpNode.SplitLC
	n.LimitLC = tmpNode.LimitLC
	n.Left = tmpNode.Left
	n.Right = tmpNode.Right

	jsonData, err := json.Marshal(tmpNode.Data)
	if err != nil {
		return err
	}

	if _, ok := tmpNode.Data["hash"]; ok {
		n.Data = NewXor()
		err = json.Unmarshal(jsonData, &n.Data)
		if err != nil {
			return err
		}
	} else if _, ok = tmpNode.Data["buckets"]; ok {
		n.Data = NewIblt(1024)
		err = json.Unmarshal(jsonData, &n.Data)
		if err != nil {
			return err
		}
	}

	return nil
}
