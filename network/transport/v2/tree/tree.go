package tree

import (
	"encoding"
	"encoding/json"
	"fmt"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"math"
)

// Data is the interface for Data held in each node of the tree
type Data interface {
	// New creates a copy of this instance that is initialized to the default/empty state.
	New() Data
	// Clone creates an exact copy using the current instance as a prototype.
	Clone() Data
	// Insert a new transaction reference.
	Insert(ref hash.SHA256Hash) error
	// Add another instance to this one. Produces an error if the underlying datastructures are not the same.
	Add(data Data) error
	// Subtract another instance from this one. Produces an error if the underlying datastructures are not the same.
	Subtract(data Data) error
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
}

// Tree
/* tree creates a binary tree, where the leaves contain Data over a fixed range of Lamport Clock (uint32) values.
The Data of the parent is the sum of that of its children. The root contains the sum of all Data in the tree.
Since the leaves are of fixed size, a new root is created when added something to an uint32 outside of the current root range.
Whenever a new branch is created, a string of Left TreeData is created all the way to the leaf.
TODO: There is some redundancy in storing the Left & Right leaf + their parent. Dropping Left leafs saves ~25% of memory.
*/
type Tree interface {
	// Insert a transaction reference at the specified clock value.
	Insert(ref hash.SHA256Hash, clock uint32) error
	// GetRoot returns the accumulated Data for the entire tree
	GetRoot() Data
	// GetZeroTo Data for uint32-range [0, ceil(clock/leafSize)*leafSize)
	GetZeroTo(clock uint32) (Data, uint32)
	// DropLeaves shrinks the tree by dropping all leaves. The parent of a leaf will become the new leaf
	DropLeaves()
	GetUpdate() (dirty map[uint32][]byte, orphaned map[uint32]struct{}, err error)
	ResetUpdate()
	Load(prototype Data, leaves map[uint32][]byte) error
}

type tree struct {
	Depth    uint8  `json:"depth"` // redundant -> Depth=2log(MaxSize/LeafSize)
	MaxSize  uint32 `json:"max_size"`
	LeafSize uint32 `json:"leaf_size"`
	Root     *node  `json:"root"`
	// storage
	dirtyLeaves    map[uint32]*node
	orphanedLeaves map[uint32]struct{}
}

// New creates a new tree with the given leafSize and of the same type of Data as the prototype.
func New(prototype Data, leafSize uint32) Tree {
	root := newNode(leafSize/2, leafSize, prototype.New())
	return &tree{
		Root:        root,
		MaxSize:     leafSize,
		LeafSize:    leafSize,
		dirtyLeaves: map[uint32]*node{root.SplitLC: root},
	}
}

func (t *tree) Load(prototype Data, leaves map[uint32][]byte) error {
	// initialize tree
	split := uint32(math.MaxUint32)
	for k, _ := range leaves {
		if k < split {
			split = k
		}
	}
	t.Depth = 0
	t.LeafSize = split * 2
	t.MaxSize = t.LeafSize
	t.dirtyLeaves = map[uint32]*node{}
	t.Root = newNode(split, t.LeafSize, prototype.New())

	// build tree
	var err error
	var leaf []byte
	for split, leaf = range leaves {
		data := prototype.New()
		err = data.UnmarshalBinary(leaf)
		if err != nil {
			return err
		}
		err = t.applyToTree(split, func(n *node) error {
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

type manipulationFn func(n *node) error

// applyToTree applies a manipulationFn from all nodes between root and leaf containing clock. If a leaf does not exist it will be created.
func (t *tree) applyToTree(clock uint32, fn manipulationFn) error {
	// grow tree if needed
	for clock >= t.MaxSize {
		t.reRoot()
	}

	// Insert ref in all TreeData from root to leave
	var current *node
	next := t.Root
	for next != nil {
		current = next
		err := fn(current)
		if err != nil {
			return fmt.Errorf("Add failed for node with splitLC at LC %d: %w", next.SplitLC, err)
		}
		next = t.getNextNode(current, clock)
	}
	t.dirtyLeaves[current.SplitLC] = current

	return nil
}

func (t *tree) newBranch(start, stop uint32) *node {
	split := (stop + start) / 2
	n := newNode(split, stop, t.Root.Data.New())
	if stop-start > t.LeafSize {
		n.Left = t.newBranch(start, split)
	} else {
		t.dirtyLeaves[n.SplitLC] = n
	}
	return n
}

// Insert a transaction reference at the specified clock value.
func (t *tree) Insert(ref hash.SHA256Hash, clock uint32) error {
	return t.applyToTree(clock, func(n *node) error {
		return n.Data.Insert(ref)
	})
	//// grow tree if needed
	//for clock >= t.MaxSize {
	//	t.reRoot()
	//}
	//
	//// Insert ref in all TreeData from root to leave
	//var current *node
	//next := t.Root
	//for next != nil {
	//	current = next
	//	err := current.Data.Insert(ref)
	//	if err != nil {
	//		return fmt.Errorf("Insert failed for node with splitLC at LC %d: %w", next.SplitLC, err)
	//	}
	//	next = t.getNextNode(current, clock)
	//}
	//t.dirtyLeaves[current.SplitLC] = current
	//
	//return nil
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
func (t *tree) getNextNode(current *node, clock uint32) *node {
	// return nil if current is a leaf
	if current.Left == nil {
		return nil
	}

	if clock < current.SplitLC {
		return current.Left
	} else {
		if current.Right == nil {
			current.Right = t.newBranch(current.SplitLC, current.LimitLC)
		}
		return current.Right
	}
}

// GetRoot returns the accumulated Data for the entire tree
func (t *tree) GetRoot() Data {
	return t.Root.Data.Clone()
}

// GetZeroTo Data for uint32-range [0, ceil(clock/leafSize)*leafSize)
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
			return data, getTrueClock(current)
		}
	}
}

// getTrueClock finds the Right most child of the given node and returns its maximum clock value.
func getTrueClock(n *node) uint32 {
	for {
		if n.Right != nil {
			n = n.Right
		} else if n.Left != nil {
			n = n.Left
		} else {
			return n.LimitLC
		}
	}
}

// GetUpdate returns dirty l
func (t *tree) GetUpdate() (dirty map[uint32][]byte, orphaned map[uint32]struct{}, err error) {
	dirty = make(map[uint32][]byte, len(t.dirtyLeaves))
	for k, v := range t.dirtyLeaves {
		b, err := v.Data.MarshalBinary()
		if err != nil {
			return nil, nil, err
		}
		dirty[k] = b
	}
	return dirty, t.orphanedLeaves, err
}

func (t *tree) ResetUpdate() {
	t.dirtyLeaves = map[uint32]*node{}
	t.orphanedLeaves = nil
}

type dropLeavesUpdate struct {
	dirty    map[uint32]*node
	orphaned map[uint32]struct{}
}

// DropLeaves shrinks the tree by dropping all leaves. The parent of a leaf will become the new leaf
func (t *tree) DropLeaves() {
	if t.Root == nil || t.Root.Left == nil {
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
	// Nothing to do if n is a leaf
	if n == nil || n.Left == nil {
		return
	}
	// if n.Left is a leaf, make n node a leaf
	if n.Left.Left == nil {
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
	// SplitLC point for Left / Right node
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
