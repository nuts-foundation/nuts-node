package tree

import (
	"encoding"
	"encoding/json"
	"fmt"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
)

const (
	leafSize = 512
)

// Data is the interface for Data held in each node of the tree
type Data interface {
	// New creates a copy of this instance that is initialized to the default/empty state.
	New() Data
	// Clone creates an exact copy using the current instance as a prototype.
	Clone() Data
	// Insert a new transaction reference.
	Insert(ref hash.SHA256Hash) error
	// Subtract another instance from this one. Produces an error if the underlying datastructures are not the same.
	Subtract(data Data) error
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
}

type dataType uint8

const (
	UnknownType dataType = 0
	XOR         dataType = 1
	IBLT        dataType = 2
)

func prototypeFrom(dType dataType) (Data, error) {
	switch dType {
	case XOR:
		return NewXor(), nil
	//case IBLT: return NewIblt(), nil
	default:
		return nil, fmt.Errorf("unknown dataType: %d", dType)
	}
}

func dataTypeFrom(prototype Data) dataType {
	switch prototype.(type) {
	case *XorHash:
		return XOR
	//case *Iblt: return IBLT
	default:
		return UnknownType
	}
}

// Tree
/* Tree creates a binary Tree, where the leaves contain Data over a fixed range of Lamport Clock (uint32) values.
The Data of the parent is the sum of that of its children. The root contains the sum of all Data in the Tree.
Since the leaves are of fixed size, a new root is created when added something to an uint32 outside of the current root range.
Whenever a new branch is created, a string of Left TreeData is created all the way to the leaf.
TODO: There is some redundancy in storing the Left & Right leaf + their parent. Dropping Left leafs saves ~25% of memory.
type Tree interface {
	// Insert a transaction reference at the specified clock value.
	Insert(ref hash.SHA256Hash, clock uint32) error
	// GetRoot returns the accumulated Data for the entire Tree
	GetRoot() Data
	// GetZeroTo Data for uint32-range [0, ceil(clock/leafSize)*leafSize)
	GetZeroTo(clock uint32) Data
	// DropLeaves shrinks the Tree by dropping all leaves. The parent of a leaf will become the new leaf
	DropLeaves()
}
*/
type Tree struct {
	Depth    uint8  `json:"depth"` // redundant
	MaxSize  uint32 `json:"max_size"`
	LeafSize uint32 `json:"leaf_size"`
	Root     *node  `json:"root"`
	// storage
	dataType    dataType
	dirtyLeaves map[uint32]*node
	dirtyMeta   bool // TODO: after calling DropLeaves(), the entire tree needs to rewritten to disk
}

// New creates a new tree with the given leafSize and of the same type of Data as the prototype.
func New(prototype Data, leafSize uint32) *Tree {
	root := newNode(leafSize/2, leafSize, prototype.New())
	return &Tree{
		Root:        root,
		MaxSize:     leafSize,
		LeafSize:    leafSize,
		dataType:    dataTypeFrom(prototype),
		dirtyLeaves: map[uint32]*node{root.SplitLC: root},
		dirtyMeta:   true,
	}
}

func (t *Tree) newBranch(start, stop uint32) *node {
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
func (t *Tree) Insert(ref hash.SHA256Hash, clock uint32) error {
	// grow tree if needed
	for clock >= t.MaxSize {
		t.reRoot()
	}

	// Insert ref in all TreeData from root to leave
	var current *node
	next := t.Root
	for next != nil {
		current = next
		err := current.Data.Insert(ref)
		if err != nil {
			return fmt.Errorf("Insert failed for node with splitLC at LC %d: %w", next.SplitLC, err)
		}
		next = t.getNextNode(current, clock)
	}
	t.dirtyLeaves[current.SplitLC] = current

	return nil
}

// reRoot creates a new Root with Data from the current Root and adds current Root as its Left branch.
func (t *Tree) reRoot() {
	newRoot := newNode(t.MaxSize, 2*t.MaxSize, t.Root.Data.Clone())
	newRoot.Left = t.Root
	t.Root = newRoot
	t.MaxSize *= 2
	t.Depth++
	t.dirtyMeta = true
}

// getNextNode retrieves the next node based on the clock value. If the node does not exist it is created.
func (t *Tree) getNextNode(current *node, clock uint32) *node {
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
func (t *Tree) GetRoot() Data {
	return t.Root.Data.Clone()
}

// GetZeroTo Data for uint32-range [0, ceil(clock/leafSize)*leafSize)
func (t *Tree) GetZeroTo(clock uint32) (Data, uint32) {
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

// DropLeaves shrinks the tree by dropping all leaves. The parent of a leaf will become the new leaf
func (t *Tree) DropLeaves() {
	if t.Root.Left != nil {
		dropLeaves(t.Root)
		t.LeafSize *= 2
		t.Depth--
	}
	t.dirtyMeta = true
}

func dropLeaves(current *node) {
	// Nothing to do if a current.Right was nil || should not drop leaf if it is the root.
	if current == nil || current.Left == nil {
		return
	}
	// if current.Left is a leaf, make current node a leaf
	if current.Left.Left == nil {
		current.Left = nil
		current.Right = nil
		return
	}
	dropLeaves(current.Left)
	dropLeaves(current.Right)
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
