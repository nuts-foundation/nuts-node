package dag

import (
	"github.com/nuts-foundation/nuts-node/network/dag/tree"
	"testing"

	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/stretchr/testify/assert"
)

func TestBboltStore_Update(t *testing.T) {
	store := newBBoltTestTreeStore(t)
	testTree := tree.New(tree.NewXor(), 512)

	err := store.Update("real bucket", testTree)
	assert.NoError(t, err)
}

func TestBboltStore_Read(t *testing.T) {
	store := newBBoltTestTreeStore(t)
	prototype := tree.NewXor()
	testTree := tree.New(prototype, 512)
	err := store.Update("real bucket", testTree)
	if !assert.NoError(t, err) {
		return
	}

	t.Run("ok - read tree successfully", func(t *testing.T) {
		tr, err := store.Read("real bucket", prototype)
		assert.NoError(t, err)
		assert.Equal(t, testTree, tr)
	})

	t.Run("fail - incorrect bucket", func(t *testing.T) {
		_, err = store.Read("fake bucket", prototype)
		assert.EqualError(t, err, "bucket 'fake bucket' not found")
	})

	t.Run("fail - incorrect prototype", func(t *testing.T) {
		_, err = store.Read("real bucket", tree.NewIblt(0))
		assert.Error(t, err)
	})
}

func newBBoltTestTreeStore(t *testing.T) *bboltTree {
	testDir := io.TestDirectory(t)
	return newBBoltTreeStore(createBBoltDB(testDir))
}
