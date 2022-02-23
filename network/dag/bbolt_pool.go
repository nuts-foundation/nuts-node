package dag

import (
	"sync"

	"go.etcd.io/bbolt"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
)

type BBoltPool struct {
	lock   sync.RWMutex
	stores map[hash.SHA256Hash]*bbolt.DB
}

func NewBBoltPool() *BBoltPool {
	return &BBoltPool{
		lock:   sync.RWMutex{},
		stores: map[hash.SHA256Hash]*bbolt.DB{},
	}
}

// Get returns a bbolt.DB from the pool
func (pool *BBoltPool) Get(idx hash.SHA256Hash) (store *bbolt.DB, ok bool) {
	pool.lock.RLock()
	defer pool.lock.RUnlock()

	store, ok = pool.stores[idx]
	return
}

// Add attaches a bbolt.DB to the pool and guarantees that the payloads bucket exists
func (pool *BBoltPool) Add(idx hash.SHA256Hash, store *bbolt.DB) error {
	if err := store.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(payloadsBucketName))
		return err
	}); err != nil {
		return err
	}

	pool.lock.Lock()
	defer pool.lock.Unlock()

	pool.stores[idx] = store

	return nil
}
