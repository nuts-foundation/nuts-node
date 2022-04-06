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
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
)

const testLeafSize = uint32(4)

func TestNew(t *testing.T) {
	emptyTree := New(NewXor(), testLeafSize).(*tree)

	// tree
	assert.Equal(t, testLeafSize, emptyTree.leafSize)
	assert.Equal(t, testLeafSize, emptyTree.treeSize)

	// root
	assert.True(t, emptyTree.root.isLeaf())
}

func TestTree_Insert(t *testing.T) {
	t.Run("insert single Tx", func(t *testing.T) {
		ref := hash.FromSlice([]byte{123})
		tr := newTestTree(NewXor(), testLeafSize)

		tr.Insert(ref, 0)

		assert.Equal(t, ref, tr.root.data.(*Xor).Hash())
	})

	t.Run("insert single Tx out of tree range", func(t *testing.T) {
		ref := hash.FromSlice([]byte{123})
		tr := newTestTree(NewXor(), testLeafSize)

		tr.Insert(ref, testLeafSize+1)

		assert.Equal(t, ref, tr.root.data.(*Xor).Hash())
		assert.Equal(t, ref, tr.root.right.data.(*Xor).Hash())
		assert.Equal(t, hash.EmptyHash(), tr.root.left.data.(*Xor).Hash())
	})
}

func TestTree_InsertGetDirty(t *testing.T) {
	t.Run("insert single TX", func(t *testing.T) {
		ref := hash.FromSlice([]byte{123})
		tr := newTestTree(NewXor(), testLeafSize)

		dirty := tr.InsertGetDirty(ref, 0)

		assert.Len(t, dirty, 1)
	})
}

func TestTree_Delete(t *testing.T) {
	t.Run("delete single Tx", func(t *testing.T) {
		ref := hash.FromSlice([]byte{123})
		tr := newTestTree(NewXor(), testLeafSize)

		tr.Delete(ref, 0)

		assert.Equal(t, ref, tr.root.data.(*Xor).Hash())
	})

	t.Run("delete single Tx out of tree range", func(t *testing.T) {
		ref := hash.FromSlice([]byte{123})
		tr := newTestTree(NewXor(), testLeafSize)

		tr.Delete(ref, testLeafSize+1)

		assert.Equal(t, ref, tr.root.data.(*Xor).Hash())
		assert.Equal(t, ref, tr.root.right.data.(*Xor).Hash())
		assert.Equal(t, hash.EmptyHash(), tr.root.left.data.(*Xor).Hash())
	})
}

func TestTree_GetRoot(t *testing.T) {
	t.Run("root Data is zero", func(t *testing.T) {
		tr := newTestTree(NewXor(), testLeafSize)

		assert.Equal(t, hash.EmptyHash(), tr.GetRoot().(*Xor).Hash())
	})

	t.Run("root after re-rooting", func(t *testing.T) {
		tr := newTestTree(NewXor(), testLeafSize)
		ref := hash.FromSlice([]byte{123})

		tr.Insert(ref, testLeafSize)

		assert.Equal(t, ref, tr.GetRoot().(*Xor).Hash())
	})

	t.Run("root of many Tx", func(t *testing.T) {
		tr := newTestTree(NewXor(), testLeafSize)
		allRefs := hash.EmptyHash()
		N := testLeafSize * 3
		var ref hash.SHA256Hash

		for i := uint32(0); i < N; i++ {
			rand.Read(ref[:])
			allRefs = allRefs.Xor(ref)
			tr.Insert(ref, N-i)
		}

		assert.Equal(t, allRefs, tr.GetRoot().(*Xor).Hash())
	})
}

func TestTree_GetZeroTo(t *testing.T) {
	tr, td := filledTestTree(NewXor(), testLeafSize)

	c0t, lc0 := tr.GetZeroTo(0 * testLeafSize)
	p0t, lc1 := tr.GetZeroTo(1 * testLeafSize)
	r0t, lc2 := tr.GetZeroTo(2 * testLeafSize)
	root, lcMax := tr.GetZeroTo(2 * tr.treeSize)

	assert.Equal(t, td.c0, c0t)
	assert.Equal(t, testLeafSize-1, lc0)
	assert.Equal(t, td.p0, p0t)
	assert.Equal(t, testLeafSize*2-1, lc1)
	assert.Equal(t, td.r, r0t)
	assert.Equal(t, testLeafSize*3-1, lc2)
	assert.Equal(t, td.r, root)
	assert.Equal(t, testLeafSize*3-1, lcMax)
}

func TestTree_rightmostLeafClock(t *testing.T) {
	tr, _ := filledTestTree(NewXor(), testLeafSize)

	clock := rightmostLeafClock(tr.root)

	assert.Equal(t, testLeafSize*3-1, clock)
}

func TestTree_DropLeaves(t *testing.T) {
	t.Run("root should not be dropped", func(t *testing.T) {
		tr := &tree{leafSize: testLeafSize, root: &node{}}

		tr.DropLeaves()

		assert.True(t, tr.root.isLeaf())
		assert.Equal(t, testLeafSize, tr.leafSize)
	})

	t.Run("drop leaves 2->1", func(t *testing.T) {
		tr := &tree{
			leafSize: testLeafSize,
			root:     &node{left: &node{left: &node{}, right: &node{}}},
		}

		tr.DropLeaves()

		assert.True(t, tr.root.left.isLeaf())
		assert.Equal(t, 2*testLeafSize, tr.leafSize)
	})

	t.Run("drop leaves 2->0", func(t *testing.T) {
		tr, _ := filledTestTree(NewXor(), testLeafSize)

		tr.DropLeaves()
		tr.DropLeaves()

		assert.True(t, tr.root.isLeaf())
		assert.Equal(t, 4*testLeafSize, tr.leafSize)
		assert.Equal(t, len(tr.orphanedLeaves), 5)
	})
}

func TestTree_reRoot(t *testing.T) {
	t.Run("single re-root", func(t *testing.T) {
		tr := newTestTree(NewXor(), testLeafSize)

		tr.reRoot()

		assert.True(t, tr.root.left.isLeaf())
		assert.Nil(t, tr.root.right)
		assert.Equal(t, tr.treeSize, 2*testLeafSize)
	})

	t.Run("double re-root", func(t *testing.T) {
		tr := newTestTree(NewXor(), testLeafSize)

		tr.reRoot()
		tr.reRoot()

		assert.True(t, tr.root.left.left.isLeaf())
		assert.Nil(t, tr.root.right)
		assert.Equal(t, tr.treeSize, 4*testLeafSize)
	})
}

func TestTree_GetUpdate(t *testing.T) {
	t.Run("dirty leaves after insert", func(t *testing.T) {
		tr := newTestTree(NewXor(), testLeafSize)
		h := hash.FromSlice([]byte{1})
		tr.Insert(h, 2*testLeafSize)

		dirty, orphaned := tr.GetUpdates()

		assert.Equal(t, 0, len(orphaned))
		assert.Equal(t, 2, len(dirty))
		_, ok := dirty[testLeafSize/2] // root from newTestTree was dirty
		assert.True(t, ok)
		_, ok = dirty[testLeafSize*5/2]
		assert.True(t, ok)
	})

	t.Run("GetUpdates does not reset update tracking", func(t *testing.T) {
		tr := newTestTree(NewXor(), testLeafSize)
		h := hash.FromSlice([]byte{1})
		tr.Insert(h, 2*testLeafSize)

		_, _ = tr.GetUpdates()
		dirty, orphaned := tr.GetUpdates()

		assert.Equal(t, 0, len(orphaned))
		assert.Equal(t, 2, len(dirty))
		_, ok := dirty[testLeafSize/2] // root from newTestTree was dirty
		assert.True(t, ok)
		_, ok = dirty[testLeafSize*5/2]
		assert.True(t, ok)
	})

	t.Run("dropLeaves has updates and orphans", func(t *testing.T) {
		tr, _ := filledTestTree(NewXor(), testLeafSize)
		tr.DropLeaves()

		dirty, orphaned := tr.GetUpdates()

		assert.Equal(t, 3, len(orphaned))
		assert.Equal(t, 2, len(dirty))
		_, ok := dirty[testLeafSize]
		assert.True(t, ok)
		_, ok = dirty[testLeafSize*3]
		assert.True(t, ok)
	})
}

func TestTree_ResetUpdate(t *testing.T) {
	tr, _ := filledTestTree(NewXor(), testLeafSize)
	tr.DropLeaves()

	dirty, orphaned := tr.GetUpdates()
	tr.ResetUpdate()
	dirtyReset, orphanedReset := tr.GetUpdates()

	assert.Equal(t, 3, len(orphaned))
	assert.Equal(t, 0, len(orphanedReset))
	assert.Equal(t, 2, len(dirty))
	assert.Equal(t, 0, len(dirtyReset))
}

func TestTree_Load(t *testing.T) {
	t.Run("ok - tree reconstructed from bytes", func(t *testing.T) {
		tr, _ := filledTestTree(NewXor(), testLeafSize)
		dirty, _ := tr.GetUpdates()
		loadedTree := New(NewXor(), 0).(*tree)

		err := loadedTree.Load(dirty)

		assert.NoError(t, err)
		assert.Equal(t, testLeafSize, loadedTree.leafSize)
		assert.Equal(t, 4*testLeafSize, loadedTree.treeSize)
		assert.Equal(t, tr.root, loadedTree.root)

		for lc := testLeafSize - 1; lc < loadedTree.treeSize; lc += testLeafSize {
			expData, expLc := tr.GetZeroTo(lc)
			actualData, actualLc := loadedTree.GetZeroTo(lc)
			assert.Equal(t, expData, actualData)
			assert.Equal(t, expLc, actualLc)
		}
	})

	t.Run("fail - incorrect data prototype", func(t *testing.T) {
		tr, _ := filledTestTree(NewXor(), testLeafSize)
		dirty, _ := tr.GetUpdates()
		loadedTree := New(NewIblt(1024), 0)

		err := loadedTree.Load(dirty)

		assert.Error(t, err)
	})
}

// test helpers

func newTestTree(data Data, leafSize uint32) *tree {
	root := &node{
		splitLC: leafSize / 2,
		limitLC: leafSize,
		data:    data.New(),
	}
	return &tree{
		treeSize:    leafSize,
		leafSize:    leafSize,
		root:        root,
		prototype:   data.New(),
		dirtyLeaves: map[uint32]*node{root.splitLC: root},
	}
}

// filledTestTree generates a filled tree with random hashes and returns the constructed tree + expectations of the individual treeData.
func filledTestTree(data Data, leafSize uint32) (*tree, treeData) {
	/* Below are the expected results. Nodes will conform to this, use result to validate tree results.
		    (c0^c1a^c1b^c2)
			 /           \
	   (c0^c1a^c1b)      (c2)
	      /   \           / \
	   (c0) (c1a^c1b)  (c2) (nil)
	*/

	// generate test Data
	refC0 := hash.FromSlice([]byte("C0"))
	refC1a := hash.FromSlice([]byte("C1a"))
	refC1b := hash.FromSlice([]byte("C1b"))
	refC2 := hash.FromSlice([]byte("C2"))

	// create individual treeData
	c0 := data.New()
	c0.Insert(refC0)
	c1 := data.New()
	c1.Insert(refC1a)
	c1.Insert(refC1b)
	c2 := data.New()
	c2.Insert(refC2)
	p0 := c1.Clone()
	p0.Insert(refC0)
	p1 := c2.Clone()
	r := p0.Clone()
	r.Insert(refC2)
	td := treeData{r, p0, p1, c0, c1, c2, nil}

	// build tree
	tr := newTestTree(data, leafSize)
	tr.Insert(refC0, 0)
	tr.Insert(refC1a, leafSize)
	tr.Insert(refC2, leafSize*2)
	tr.Insert(refC1b, leafSize+1) // inserted after tree is reRooted
	return tr, td
}

/* treeData for the following structure
       r
	   / \
    p0   p1
   / \   / \
  c0 c1 c2 c3
*/
type treeData struct {
	r, p0, p1, c0, c1, c2, c3 Data
}
