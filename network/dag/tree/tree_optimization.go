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

func (t *bottomup) Load(leaves map[uint32][]byte) error {
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
	nodes := make([]*node, len(keys))
	var err error
	for i, k := range keys {
		nodes[i] = &node{
			splitLC: k,
			limitLC: k + halfNode,
			data:    t.prototype.New(),
		}
		if err = nodes[i].data.UnmarshalBinary(leaves[k]); err != nil {
			return err
		}
	}

	// build tree
	for len(nodes) > 1 {
		halfNode *= 2
		for i := 0; i < len(nodes); i++ {
			// left child
			nodes[i/2] = &node{
				splitLC: nodes[i].limitLC,
				limitLC: nodes[i].limitLC + halfNode,
				data:    nodes[i].data.Clone(),
				left:    nodes[i],
			}
			// right child if it exists
			i++
			if i < len(nodes) {
				if err = nodes[i/2].data.Add(nodes[i].data); err != nil {
					return err
				}
				nodes[i/2].right = nodes[i]
			}
		}
		nodes = nodes[:(len(nodes)+1)/2]
	}

	// set tree values
	t.root = nodes[0]
	t.leafSize = 2 * keys[0]
	t.treeSize = t.root.limitLC
	t.ResetUpdate()

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
