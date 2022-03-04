package tree

import (
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/assert"
	"math/rand"
	"testing"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
)

const testLeafSize = uint32(4)

func TestNew(t *testing.T) {
	emptyTree := New(NewXor(), testLeafSize)

	// tree
	assert.Equal(t, uint8(0), emptyTree.Depth)
	assert.Equal(t, testLeafSize, emptyTree.LeafSize)
	assert.Equal(t, testLeafSize, emptyTree.MaxSize)

	// root
	assert.True(t, emptyTree.Root.isLeaf())
}

func TestTree_Insert(t *testing.T) {
	t.Run("insert single Tx", func(t *testing.T) {
		ref := hash.FromSlice([]byte{123})
		tr := newTestTree(NewXor(), testLeafSize)

		_ = tr.Insert(ref, 0)

		assert.Equal(t, ref, hashFromXor(tr.Root))
	})

	t.Run("insert single Tx out of tree range", func(t *testing.T) {
		ref := hash.FromSlice([]byte{123})
		tr := newTestTree(NewXor(), testLeafSize)

		_ = tr.Insert(ref, testLeafSize+1)

		assert.Equal(t, ref, hashFromXor(tr.Root))
		assert.Equal(t, ref, hashFromXor(tr.Root.Right))
		assert.Equal(t, hash.EmptyHash(), hashFromXor(tr.Root.Left))
	})
}

func TestTree_GetRoot(t *testing.T) {
	t.Run("root Data is zero", func(t *testing.T) {
		tr := newTestTree(NewXor(), testLeafSize)

		assert.Equal(t, hash.EmptyHash(), hashFromXor(tr.Root))
	})

	t.Run("root after re-rooting", func(t *testing.T) {
		tr := newTestTree(NewXor(), testLeafSize)
		ref := hash.FromSlice([]byte{123})

		_ = tr.Insert(ref, testLeafSize)

		assert.Equal(t, ref, hashFromXor(tr.Root))
	})

	t.Run("root of many Tx", func(t *testing.T) {
		tr := newTestTree(NewXor(), testLeafSize)
		allRefs := hash.EmptyHash()
		N := testLeafSize * 3
		var ref hash.SHA256Hash

		for i := uint32(0); i < N; i++ {
			rand.Read(ref[:])
			xor(&allRefs, allRefs, ref)
			_ = tr.Insert(ref, N-i)
		}

		assert.Equal(t, allRefs, hashFromXor(tr.Root))
	})
}

func TestTree_GetZeroTo(t *testing.T) {
	tr, td := filledTestTree(NewXor(), testLeafSize)

	c0t, lc0 := tr.GetZeroTo(0 * testLeafSize)
	p0t, lc1 := tr.GetZeroTo(1 * testLeafSize)
	r0t, lc2 := tr.GetZeroTo(2 * testLeafSize)
	root, lcMax := tr.GetZeroTo(2 * tr.MaxSize)

	assert.Equal(t, td.c0, c0t)
	assert.Equal(t, testLeafSize-1, lc0)
	assert.Equal(t, td.p0, p0t)
	assert.Equal(t, testLeafSize*2-1, lc1)
	assert.Equal(t, td.r, r0t)
	assert.Equal(t, testLeafSize*3-1, lc2)
	assert.Equal(t, td.r, root)
	assert.Equal(t, testLeafSize*3-1, lcMax)
}

func TestTree_DropLeaves(t *testing.T) {
	t.Run("root should not be dropped", func(t *testing.T) {
		tr := &tree{Depth: 0, LeafSize: testLeafSize, Root: &node{}}

		tr.DropLeaves()

		assert.True(t, tr.Root.isLeaf())
		assert.Equal(t, uint8(0), tr.Depth)
		assert.Equal(t, testLeafSize, tr.LeafSize)
	})

	t.Run("drop leaves 2->1", func(t *testing.T) {
		tr := &tree{
			Depth:    2,
			LeafSize: testLeafSize,
			Root:     &node{Left: &node{Left: &node{}, Right: &node{}}},
		}

		tr.DropLeaves()

		assert.True(t, tr.Root.Left.isLeaf())
		assert.Equal(t, uint8(1), tr.Depth)
		assert.Equal(t, 2*testLeafSize, tr.LeafSize)
	})
}

func TestTree_reRoot(t *testing.T) {
	t.Run("single re-root", func(t *testing.T) {
		tr := newTestTree(NewXor(), testLeafSize)

		tr.reRoot()

		assert.True(t, tr.Root.Left.isLeaf())
		assert.Nil(t, tr.Root.Right)
		assert.Equal(t, tr.MaxSize, 2*testLeafSize)
		assert.Equal(t, uint8(1), tr.Depth)
	})

	t.Run("double re-root", func(t *testing.T) {
		tr := newTestTree(NewXor(), testLeafSize)

		tr.reRoot()
		tr.reRoot()

		assert.True(t, tr.Root.Left.Left.isLeaf())
		assert.Nil(t, tr.Root.Right)
		assert.Equal(t, tr.MaxSize, 4*testLeafSize)
		assert.Equal(t, uint8(2), tr.Depth)
	})
}

func TestTree_GetUpdate(t *testing.T) {
	t.Run("dirty leaves after insert", func(t *testing.T) {
		tr := newTestTree(NewXor(), testLeafSize)
		h := hash.FromSlice([]byte{1})
		_ = tr.Insert(h, 2*testLeafSize)

		dirty, orphaned, err := tr.GetUpdate()

		assert.NoError(t, err)
		assert.Equal(t, 0, len(orphaned))
		assert.Equal(t, 2, len(dirty))
		_, ok := dirty[testLeafSize/2] // root from newTestTree was dirty
		assert.True(t, ok)
		_, ok = dirty[testLeafSize*5/2]
		assert.True(t, ok)
	})

	t.Run("DropLeaves has updates and orphans", func(t *testing.T) {
		tr, _ := filledTestTree(NewXor(), testLeafSize)
		tr.DropLeaves()

		dirty, orphaned, err := tr.GetUpdate()

		assert.NoError(t, err)
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

	dirty, orphaned, err := tr.GetUpdate()
	tr.ResetUpdate()
	dirtyReset, orphanedReset, err := tr.GetUpdate()

	assert.NoError(t, err)
	assert.Equal(t, 3, len(orphaned))
	assert.Equal(t, 0, len(orphanedReset))
	assert.Equal(t, 2, len(dirty))
	assert.Equal(t, 0, len(dirtyReset))
}

func TestTree_Load(t *testing.T) {
	// TODO
}

var jsonTestData = []byte(
	`{"depth":2,"max_size":16,"leaf_size":4,
	"root":{"split":8,"limit":16,"data":{"hash":"0002030000000000000000000000000000000000000000000000000000000000"},
		"left":{"split":4,"limit":8,"data":{"hash":"4330030000000000000000000000000000000000000000000000000000000000"},
			"left":{"split":2,"limit":4,"data":{"hash":"4330000000000000000000000000000000000000000000000000000000000000"}},
			"right":{"split":6,"limit":8,"data":{"hash":"0000030000000000000000000000000000000000000000000000000000000000"}}},
		"right":{"split":12,"limit":16,"data":{"hash":"4332000000000000000000000000000000000000000000000000000000000000"},
			"left":{"split":10,"limit":12,"data":{"hash":"4332000000000000000000000000000000000000000000000000000000000000"}}}}}`)

func TestTree_MarshalJSON(t *testing.T) {
	tr, _ := filledTestTree(NewXor(), 4)

	jsonData, err := json.Marshal(tr)
	fmt.Println(string(jsonData))
	if !assert.NoError(t, err) {
		return
	}
	assert.JSONEq(t, string(jsonTestData), string(jsonData))
}

func TestTree_UnmarshalJSON(t *testing.T) {
	_, treeD := filledTestTree(NewXor(), 4)
	tr := tree{}

	err := json.Unmarshal(jsonTestData, &tr)

	assert.NoError(t, err)
	assert.Equal(t, uint8(2), tr.Depth)
	assert.Equal(t, uint32(16), tr.MaxSize)
	assert.Equal(t, uint32(4), tr.LeafSize)
	assert.True(t, nodeEquals(tr.Root, 8, 16, treeD.r.(*Xor).Hash))
	assert.True(t, nodeEquals(tr.Root.Left, 4, 8, treeD.p0.(*Xor).Hash))
	assert.True(t, nodeEquals(tr.Root.Left.Left, 2, 4, treeD.c0.(*Xor).Hash))
	assert.True(t, nodeEquals(tr.Root.Right, 12, 16, treeD.c2.(*Xor).Hash))
	assert.Nil(t, tr.Root.Right.Right)
}

// test helpers

func nodeEquals(n *node, split, limit uint32, hash hash.SHA256Hash) bool {
	return n != nil && n.SplitLC == split && n.LimitLC == limit && hashFromXor(n) == hash
}

func hashFromXor(n *node) hash.SHA256Hash {
	return n.Data.(*Xor).Hash
}

func newTestTree(data Data, leafSize uint32) *tree {
	root := &node{
		SplitLC: leafSize / 2,
		LimitLC: leafSize,
		Data:    data.New(),
	}
	return &tree{
		Depth:       0,
		MaxSize:     leafSize,
		LeafSize:    leafSize,
		Root:        root,
		prototype:   data.New(),
		dirtyLeaves: map[uint32]*node{root.SplitLC: root},
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
	_ = c0.Insert(refC0)
	c1 := data.New()
	_ = c1.Insert(refC1a)
	_ = c1.Insert(refC1b)
	c2 := data.New()
	_ = c2.Insert(refC2)
	p0 := c1.Clone()
	_ = p0.Insert(refC0)
	p1 := c2.Clone()
	r := p0.Clone()
	_ = r.Insert(refC2)
	td := treeData{r, p0, p1, c0, c1, c2, nil}

	// build tree
	tr := newTestTree(data, leafSize)
	_ = tr.Insert(refC0, 0)
	_ = tr.Insert(refC1a, leafSize)
	_ = tr.Insert(refC2, leafSize*2)
	_ = tr.Insert(refC1b, leafSize+1) // inserted after tree is reRooted
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
