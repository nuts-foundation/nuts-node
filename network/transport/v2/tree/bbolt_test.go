package tree

import (
	"crypto/rand"
	"fmt"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/stretchr/testify/assert"
	"go.etcd.io/bbolt"
	"testing"
)

func newBBoltTestStore(t *testing.T) *bboltStore {
	opts := *bbolt.DefaultOptions
	opts.NoSync = true

	testDir := io.TestDirectory(t)

	store := NewBBoltStore().(*bboltStore)
	err := store.Configure(core.ServerConfig{Datadir: testDir})
	assert.NoError(t, err)

	return store
}

func TestBboltStore_Configure(t *testing.T) {
	t.Run("error - unable to create DB", func(t *testing.T) {
		store := NewBBoltStore().(core.Configurable)

		err := store.Configure(core.ServerConfig{Datadir: "bbolt_test.go"})

		assert.Error(t, err)
	})
}

func TestBBoltStore_Start(t *testing.T) {
	store := NewBBoltStore().(core.Runnable)

	err := store.Start()

	assert.NoError(t, err)
}

func TestBBoltStore_Shutdown(t *testing.T) {
	store := NewBBoltStore().(core.Runnable)

	err := store.Shutdown()

	assert.NoError(t, err)
}

func TestBboltStore_Read(t *testing.T) {
	store := newBBoltTestStore(t)
	assert.NoError(t, store.Start())
	testTree, _ := filledTestTree(NewIblt(ibltNumBuckets), 512)
	fmt.Println(testTree)
	testTree.DropLeaves()
	fmt.Println(testTree)
	emptyTree := New(NewIblt(ibltNumBuckets), 0)
	fmt.Println(emptyTree)

	err := store.Update(ibltBucketName, testTree)
	assert.NoError(t, err)

	err = store.Read(ibltBucketName, emptyTree)
	assert.NoError(t, err)

	err = store.Read(xorBucketName, emptyTree)
	assert.Error(t, err)

	fmt.Println(emptyTree)
	//fmt.Println(testTree.GetRoot().(*Xor).Hash)
	//fmt.Println(emptyTree.GetRoot().(*Xor).Hash)
}

func TestBboltStore_Update(t *testing.T) {
	store := newBBoltTestStore(t)
	assert.NoError(t, store.Start())
	testTree := newTestTree(NewXor(), 512)

	err := store.Update(xorBucketName, testTree)
	assert.NoError(t, err)
}

func BenchmarkBboltStore_Update(b *testing.B) {
	testDir := "/Users/gerard.snaauw/Desktop/trees/" // TODO: remove
	store := NewBBoltStore().(*bboltStore)
	err := store.Configure(core.ServerConfig{Datadir: testDir})
	if err != nil {
		b.Log(err)
		b.FailNow()
	}
	defer func(store *bboltStore) {
		err := store.Shutdown()
		if err != nil {
			b.Log(err)
		}
	}(store)
	testTree := newTestTree(NewXor(), 512)

	var h hash.SHA256Hash

	for i := 0; i < b.N; i++ {
		_, _ = rand.Read(h[:])
		_ = testTree.Insert(h, 0)
		err := store.Update(xorBucketName, testTree)
		if err != nil {
			b.Log(err)
			b.FailNow()
		}
	}
}
