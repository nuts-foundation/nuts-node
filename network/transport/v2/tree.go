package v2

import (
	"fmt"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
)

/* tree creates a binary tree, where the leaves contain Data over a fixed range of Lamport Clock (uint32) values.
The Data of the parent is the sum of that of its children. The root contains the sum of all Data in the tree.
Since the leaves are of fixed size, a new root is created when added something to an uint32 outside of the current root range.
Whenever a new branch is created, a string of left nodes is created all the way to the leaf.
TODO: There is some redundancy in storing the left & right leaf + their parent. Dropping left leafs saves ~25% of memory.
type tree interface {
	// insert a transaction reference at the specified clock value.
	insert(ref hash.SHA256Hash, clock uint32) error
	// getRoot returns the accumulated data for the entire tree
	getRoot() TreeData
	// getZeroTo Data for uint32-range [0, ceil(clock/leafSize)*leafSize)
	getZeroTo(clock uint32) TreeData
	// dropLeaves shrinks the tree by dropping all leaves. The parent of a leaf will become the new leaf
	dropLeaves()
}
*/
type tree struct {
	root        *node
	maxTreeSize uint32
	maxKnownLC  uint32
	leafSize    uint32
}

// newTree creates a new tree with the given leafSize and of the same type of TreeData as the prototype.
func newTree(prototype TreeData, leafSize uint32) *tree {
	return &tree{
		root:        newNode(leafSize, leafSize, prototype.New()),
		maxTreeSize: leafSize,
		leafSize:    leafSize,
	}
}

func (t *tree) newBranch(start, stop uint32) *node {
	split := (stop + start) / 2
	n := newNode(split, stop, t.root.data.New())
	if stop-start > t.leafSize {
		n.left = t.newBranch(start, split)
	}
	return n
}

// insert a transaction reference at the specified clock value.
func (t *tree) insert(ref hash.SHA256Hash, clock uint32) error {
	// grow tree if needed
	for clock >= t.maxTreeSize {
		t.reRoot()
	}

	// insert ref in all nodes from root to leave
	next := t.root
	for next != nil {
		err := next.data.Insert(ref)
		if err != nil {
			return fmt.Errorf("insert failed for node with splitLC at LC %d: %w", next.splitLC, err)
		}
		next = t.getNextNode(next, clock)
	}

	if clock > t.maxKnownLC {
		t.maxKnownLC = clock
	}

	return nil
}

// reRoot creates a new root with data from the current root and adds current root as its left branch.
func (t *tree) reRoot() {
	newRoot := newNode(t.maxTreeSize, 2*t.maxTreeSize, t.root.data.Clone())
	newRoot.left = t.root
	t.root = newRoot
	t.maxTreeSize *= 2
}

// getNextNode retrieves the next node based on the clock value. If the node does not exist it is created.
func (t *tree) getNextNode(current *node, clock uint32) *node {
	// return nil if current is a leaf
	if current.left == nil {
		return nil
	}

	if clock < current.splitLC {
		return current.left
	} else {
		if current.right == nil {
			current.right = t.newBranch(current.splitLC, current.maxLC)
		}
		return current.right
	}
}

// getRoot returns the accumulated data for the entire tree
func (t *tree) getRoot() (TreeData, uint32) {
	return t.root.data.Clone(), t.maxKnownLC
}

// getZeroTo Data for uint32-range [0, ceil(clock/leafSize)*leafSize)
func (t *tree) getZeroTo(clock uint32) (TreeData, uint32) {
	data := t.root.data.Clone()
	next := t.root
	for {
		current := next
		if clock < current.splitLC {
			if current.right != nil {
				// Only fails when data structures do not match, which should not happen for data managed by the tree.
				_ = data.Subtract(current.right.data)
			}
			next = current.left
		} else {
			next = current.right
		}
		if next == nil {
			return data, getTrueClock(current)
		}
	}
}

// getTrueClock finds the right most child of the given node and returns its maximum clock value.
func getTrueClock(n *node) uint32 {
	for {
		if n.right != nil {
			n = n.right
		} else if n.left != nil {
			n = n.left
		} else {
			return n.maxLC
		}
	}
}

// dropLeaves shrinks the tree by dropping all leaves. The parent of a leaf will become the new leaf
func (t *tree) dropLeaves() {
	if t.root.left != nil {
		_dropLeaves(t.root)
		t.leafSize *= 2
	}
}

func _dropLeaves(current *node) {
	// Nothing to do if a current.right was nil || should not drop leaf if it is the root.
	if current == nil || current.left == nil {
		return
	}
	// if current.left is a leaf, make current node a leaf
	if current.left.left == nil {
		current.left = nil
		current.right = nil
		return
	}
	_dropLeaves(current.left)
	_dropLeaves(current.right)
}

// node
type node struct {
	// splitLC point for left / right node
	splitLC uint32
	// maxLC clock value for the node
	maxLC uint32
	// data held by the node. Should not be nil
	data TreeData

	// child nodes. if left == nil, current node is a leaf
	left  *node
	right *node
}

func newNode(splitLC, maxLC uint32, data TreeData) *node {
	return &node{
		splitLC: splitLC,
		maxLC:   maxLC,
		data:    data,
	}
}

type TreeData interface {
	// New creates a copy of this instance that is initialized to the default/empty state.
	New() TreeData
	// Clone creates an exact copy using the current instance as a prototype.
	Clone() TreeData
	// Insert a new transaction reference.
	Insert(ref hash.SHA256Hash) error
	// Subtract another instance from this one. Produces an error if the underlying datastructures are not the same.
	Subtract(data TreeData) error
}

func xor(dest *hash.SHA256Hash, left, right hash.SHA256Hash) {
	for i := 0; i < len(left); i++ {
		dest[i] = left[i] ^ right[i]
	}
}

// XOR
type xorData struct {
	hash hash.SHA256Hash
}

func NewXor() TreeData {
	return &xorData{hash: hash.EmptyHash()}
}

func (x xorData) New() TreeData {
	return NewXor()
}

func (x *xorData) Clone() TreeData {
	clone := x.New()
	_ = clone.Insert(x.hash)
	return clone
}

func (x *xorData) Insert(ref hash.SHA256Hash) error {
	xor(&x.hash, x.hash, ref)
	return nil
}

func (x *xorData) Subtract(data TreeData) error {
	switch v := data.(type) {
	case *xorData:
		xor(&x.hash, x.hash, v.hash)
		return nil
	default:
		return fmt.Errorf("subtraction failed - expected type %T, got %T", x, v)
	}
}
