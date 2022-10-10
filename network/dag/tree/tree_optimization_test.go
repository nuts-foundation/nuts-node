package tree

import (
	"sort"
)

type bottomup struct {
	*tree
}

func NewBottomUp(prototype Data, leafSize uint32) Tree {
	tr := &bottomup{&tree{prototype: prototype.New()}}
	tr.resetDefaults(leafSize)
	return tr
}

func (b *bottomup) Load(leaves map[uint32][]byte) error {
	// nothing to load
	if len(leaves) == 0 {
		return nil
	}

	// unmarshal leaves in order
	keys := make([]uint32, 0, len(leaves))
	for k := range leaves {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i] < keys[j]
	})

	halfNode := keys[0]
	children := make([]*node, len(keys))
	var child *node
	var err error
	for i, k := range keys {
		child = &node{
			splitLC: k,
			limitLC: k + halfNode,
			data:    b.prototype.New(),
		}
		if err = child.data.UnmarshalBinary(leaves[k]); err != nil {
			return err
		}
		children[i] = child
	}

	// build tree
	parents := make([]*node, 0, (len(keys)+1)/2)
	var parent *node
	for len(children) > 1 {
		halfNode *= 2
		for i := 0; i < len(children); i++ {
			// left child
			child = children[i]
			parent = &node{
				splitLC: child.limitLC,
				limitLC: child.limitLC + halfNode,
				data:    child.data.Clone(),
				left:    child,
			}
			// right child if it exists
			i++
			if i < len(children) {
				child = children[i]
				if err = parent.data.Add(child.data); err != nil {
					return err
				}
				parent.right = child
			}
			parents = append(parents, parent)
		}
		children = parents
		parents = make([]*node, 0, (len(keys)+1)/2)
	}

	// set tree values
	b.root = children[0]
	b.leafSize = 2 * keys[0]
	b.treeSize = b.root.limitLC
	b.ResetUpdate()

	return nil
}

// Same as bottomup, only terminates after Unmarshaling (so doesn't actually Load the tree)
type bottomupUnmarshal struct {
	*tree
}

func NewBottomUpUnmarshal(prototype Data, leafSize uint32) Tree {
	tr := &bottomupUnmarshal{&tree{prototype: prototype.New()}}
	tr.resetDefaults(leafSize)
	return tr
}
func (b *bottomupUnmarshal) Load(leaves map[uint32][]byte) error {
	// nothing to load
	if len(leaves) == 0 {
		return nil
	}

	// unmarshal leaves in order
	keys := make([]uint32, 0, len(leaves))
	for k := range leaves {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i] < keys[j]
	})

	halfNode := keys[0]
	children := make([]*node, len(keys))
	var child *node
	var err error
	for i, k := range keys {
		child = &node{
			splitLC: k,
			limitLC: k + halfNode,
			data:    b.prototype.New(),
		}
		if err = child.data.UnmarshalBinary(leaves[k]); err != nil {
			return err
		}
		children[i] = child
	}

	return nil
}

type bottomupSort struct {
	*tree
}

// Same as bottomup, only terminates after sorting of leaves (so doesn't actually Load the tree)
func NewBottomUpSort(prototype Data, leafSize uint32) Tree {
	tr := &bottomupSort{&tree{prototype: prototype.New()}}
	tr.resetDefaults(leafSize)
	return tr
}
func (b *bottomupSort) Load(leaves map[uint32][]byte) error {
	// nothing to load
	if len(leaves) == 0 {
		return nil
	}

	// unmarshal leaves in order
	keys := make([]uint32, 0, len(leaves))
	for k := range leaves {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i] < keys[j]
	})

	return nil
}
