package tree

import (
	"crypto/rand"
	"encoding/json"
	"github.com/stretchr/testify/assert"
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
	assert.NotNil(t, emptyTree.Root)
	assert.Nil(t, emptyTree.Root.Left)
	assert.Nil(t, emptyTree.Root.Right)
}

func TestTree_Insert(t *testing.T) {
	if hash.EmptyHash() == generateTxRef() && !assert.NotEqual(t, hash.EmptyHash(), generateTxRef(), "Generated hashes should not be zero. This invalidates results of other tests.") {
		t.FailNow()
	}

	t.Run("insert single Tx", func(t *testing.T) {
		ref := generateTxRef()
		tr := newTree(NewXor(), testLeafSize)

		_ = tr.Insert(ref, 0)

		assert.Equal(t, ref, hashFromXor(tr.Root))
	})

	t.Run("insert single Tx out of Tree range", func(t *testing.T) {
		ref := generateTxRef()
		tr := newTree(NewXor(), testLeafSize)

		_ = tr.Insert(ref, testLeafSize+1)

		assert.Equal(t, ref, hashFromXor(tr.Root))
		assert.Equal(t, ref, hashFromXor(tr.Root.Right))
		assert.Equal(t, hash.EmptyHash(), hashFromXor(tr.Root.Left))
	})

	t.Run("insert multiple Tx", func(t *testing.T) {
		tr, td := filledTree(NewXor(), testLeafSize)

		assert.NotEqual(t, td.c0, tr.Root.Data) // sanity check
		assert.Equal(t, td.c0, tr.Root.Left.Left.Data)
		assert.Equal(t, td.c1, tr.Root.Left.Right.Data)
		assert.Equal(t, td.c2, tr.Root.Right.Left.Data)
		assert.Nil(t, tr.Root.Right.Right)

		assert.Equal(t, td.p0, tr.Root.Left.Data)
		assert.Equal(t, td.p1, tr.Root.Right.Data)

		assert.Equal(t, td.r, tr.Root.Data)
	})
}

func TestTree_GetRoot(t *testing.T) {
	t.Run("root Data is zero", func(t *testing.T) {
		tr := newTree(NewXor(), testLeafSize)

		assert.Equal(t, hash.EmptyHash(), hashFromXor(tr.Root))
	})

	t.Run("root Data is zero", func(t *testing.T) {
		tr := newTree(NewXor(), testLeafSize)
		ref := generateTxRef()

		_ = tr.Insert(ref, 0)

		assert.Equal(t, ref, hashFromXor(tr.Root))
	})

	t.Run("root after re-rooting", func(t *testing.T) {
		tr := newTree(NewXor(), testLeafSize)
		ref := generateTxRef()

		_ = tr.Insert(ref, testLeafSize)

		assert.Equal(t, ref, hashFromXor(tr.Root))
	})

	t.Run("root of many Tx", func(t *testing.T) {
		tr := newTree(NewXor(), testLeafSize)

		allRefs := hash.EmptyHash()
		N := testLeafSize * 3
		for i := uint32(0); i < N; i++ {
			ref := generateTxRef()
			xor(&allRefs, allRefs, ref)
			_ = tr.Insert(ref, N-i)
		}

		assert.Equal(t, allRefs, hashFromXor(tr.Root))
	})
}

func TestTree_GetZeroTo(t *testing.T) {
	tr, td := filledTree(NewXor(), testLeafSize)

	c0t, _ := tr.GetZeroTo(0 * testLeafSize)
	p0t, _ := tr.GetZeroTo(1 * testLeafSize)
	r0t, _ := tr.GetZeroTo(2 * testLeafSize)
	root, _ := tr.GetZeroTo(2 * tr.MaxSize)

	assert.Equal(t, td.c0, c0t)
	assert.Equal(t, td.p0, p0t)
	assert.Equal(t, td.r, r0t)
	assert.Equal(t, td.r, root)
}

func TestTree_DropLeaves(t *testing.T) {
	t.Run("root should not be dropped", func(t *testing.T) {
		tr := &Tree{Depth: 0, LeafSize: testLeafSize, Root: &node{}}

		tr.DropLeaves()

		assert.NotNil(t, tr.Root)
		assert.Nil(t, tr.Root.Left)
		assert.Nil(t, tr.Root.Right)
		assert.Equal(t, uint8(0), tr.Depth)
		assert.Equal(t, testLeafSize, tr.LeafSize)
	})

	t.Run("drop leaves 1->0", func(t *testing.T) {
		tr := &Tree{Depth: 1, LeafSize: testLeafSize, Root: &node{Left: &node{}, Right: &node{}}}

		tr.DropLeaves()

		assert.NotNil(t, tr.Root)
		assert.Nil(t, tr.Root.Left)
		assert.Nil(t, tr.Root.Right)
		assert.Equal(t, uint8(0), tr.Depth)
		assert.Equal(t, testLeafSize*2, tr.LeafSize)
	})

	t.Run("drop leaves 2->1", func(t *testing.T) {
		tr := &Tree{Depth: 2, LeafSize: testLeafSize, Root: &node{Left: &node{Left: &node{}, Right: &node{}}}}

		tr.DropLeaves()

		assert.NotNil(t, tr.Root)
		assert.NotNil(t, tr.Root.Left)
		assert.Nil(t, tr.Root.Right)
		assert.Equal(t, uint8(1), tr.Depth)
		assert.Equal(t, testLeafSize*2, tr.LeafSize)
	})

	t.Run("drop leaves 2->0", func(t *testing.T) {
		tr := &Tree{Depth: 2, LeafSize: testLeafSize, Root: &node{Left: &node{Left: &node{}}, Right: &node{}}}

		tr.DropLeaves()
		tr.DropLeaves()

		assert.NotNil(t, tr.Root)
		assert.Nil(t, tr.Root.Left)
		assert.Nil(t, tr.Root.Right)
		assert.Equal(t, uint8(0), tr.Depth)
		assert.Equal(t, testLeafSize*4, tr.LeafSize)
	})
}

func TestTree_reRoot(t *testing.T) {
	t.Run("single re-root", func(t *testing.T) {
		tr := newTree(NewXor(), testLeafSize)

		tr.reRoot()

		assert.NotNil(t, tr.Root)
		assert.NotNil(t, tr.Root.Left)
		assert.Nil(t, tr.Root.Right)
		assert.Equal(t, tr.MaxSize, 2*testLeafSize)
		assert.Equal(t, uint8(1), tr.Depth)
	})

	t.Run("double re-root", func(t *testing.T) {
		tr := newTree(NewXor(), testLeafSize)

		tr.reRoot()
		tr.reRoot()

		assert.NotNil(t, tr.Root)
		assert.NotNil(t, tr.Root.Left)
		assert.NotNil(t, tr.Root.Left.Left)
		assert.Nil(t, tr.Root.Right)
		assert.Nil(t, tr.Root.Left.Right)
		assert.Equal(t, tr.MaxSize, 4*testLeafSize)
		assert.Equal(t, uint8(2), tr.Depth)
	})
}

func TestTree_MarshalJSON(t *testing.T) {
	tr, _ := filledTree(NewXor(), testLeafSize)

	//jsonData, err := tr.MarshalJSON()
	jsonData, err := json.MarshalIndent(tr, "", "\t")
	if !assert.NoError(t, err) {
		return
	}
	t.Log(string(jsonData))
}

func TestTree_UnmarshalJSON(t *testing.T) {
	jsonData := []byte(`{
		"depth":2,"max_size":16,"leaf_size":4,
		"root":{"split":8,"limit":16,"data":{"hash":"19f1578bbe094fb50e3f21f0cb6c6524dcef1cb0961f6fe53de457b260f107fc"},
			"left":{"split":4,"limit":8,"data":{"hash":"3882f58084d85ab3929343a3bccfda70fa15c7365a85b80cc623f9879d27517f"},
				"left":{"split":2,"limit":4,"data":{"hash":"1b85cbc0a54c37a4f309bbb1d9fea705ae1139db75da04a005953c624f7c31af"}},
				"right":{"split":6,"limit":8,"data":{"hash":"23073e4021946d17619af81265317d755404feed2f5fbcacc3b6c5e5d25b60d0"}}},
			"right":{"split":12,"limit":16,"data":{"hash":"2173a20b3ad115069cac625377a3bf5426fadb86cc9ad7e9fbc7ae35fdd65683"},
				"left":{"split":10,"limit":12,"data":{"hash":"2173a20b3ad115069cac625377a3bf5426fadb86cc9ad7e9fbc7ae35fdd65683"}}}}}`)

	tr := Tree{}
	err := json.Unmarshal(jsonData, &tr)

	assert.NoError(t, err)
	assert.Equal(t, uint8(2), tr.Depth)
	assert.Equal(t, uint32(16), tr.MaxSize)
	assert.Equal(t, uint32(4), tr.LeafSize)
	assert.True(t, nodeEquals(tr.Root, 8, 16, "19f1578bbe094fb50e3f21f0cb6c6524dcef1cb0961f6fe53de457b260f107fc"))
	assert.True(t, nodeEquals(tr.Root.Left, 4, 8, "3882f58084d85ab3929343a3bccfda70fa15c7365a85b80cc623f9879d27517f"))
	assert.True(t, nodeEquals(tr.Root.Left.Left, 2, 4, "1b85cbc0a54c37a4f309bbb1d9fea705ae1139db75da04a005953c624f7c31af"))
	assert.True(t, nodeEquals(tr.Root.Right, 12, 16, "2173a20b3ad115069cac625377a3bf5426fadb86cc9ad7e9fbc7ae35fdd65683"))
	assert.Nil(t, tr.Root.Right.Right)
}

// test functions

func nodeEquals(n *node, split, limit uint32, hashString string) bool {
	return n != nil && n.SplitLC == split && n.LimitLC == limit && hashFromXor(n).String() == hashString
}

func hashFromXor(n *node) hash.SHA256Hash {
	return n.Data.(*XorHash).Hash
}

func newTree(data Data, leafSize uint32) *Tree {
	root := &node{
		SplitLC: leafSize / 2,
		LimitLC: leafSize,
		Data:    data.New(),
	}
	return &Tree{
		Depth:       0,
		MaxSize:     leafSize,
		LeafSize:    leafSize,
		Root:        root,
		dataType:    dataTypeFrom(data),
		dirtyLeaves: map[uint32]*node{root.SplitLC: root},
		dirtyMeta:   true,
	}
}

// generateTxRef creates a new random hash
func generateTxRef() hash.SHA256Hash {
	ref := hash.EmptyHash()
	rand.Read(ref[:])
	return ref
}

// filledTree generates a filled tree with random hashes and returns the constructed tree + expectations of the individual TreeData.
func filledTree(data Data, leafSize uint32) (*Tree, TreeData) {
	/* Below are the expected results. Nodes will conform to this, use result to validate tree results.
		    (c0+c1a+c1b+c2)
			 /           \
	   (c0+c1a+c1b)      (c2)
	      /   \           / \
	   (c0) (c1a+c1b)  (c2) (nil)
	*/

	// generate test Data
	refC0 := generateTxRef()
	refC1a := generateTxRef()
	refC1b := generateTxRef()
	refC2 := generateTxRef()

	// create individual TreeData
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
	td := TreeData{r, p0, p1, c0, c1, c2, nil}

	// build tree
	tr := newTree(data, leafSize)
	_ = tr.Insert(refC0, 0)
	_ = tr.Insert(refC1a, leafSize)
	_ = tr.Insert(refC2, leafSize*2)
	_ = tr.Insert(refC1b, leafSize+1) // inserted after tree is reRooted
	return tr, td
}

/* TreeData for the following structure
        r
	   / \
     p0   p1
    / \   / \
   c0 c1 c2 c3
*/
type TreeData struct {
	r, p0, p1, c0, c1, c2, c3 Data
}
