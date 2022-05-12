package storage

import (
	"github.com/nuts-foundation/nuts-node/core"
	"go.etcd.io/bbolt"
)

func NewTestStorageEngine(testDirectory string) Engine {
	result := New()
	_ = result.Configure(core.ServerConfig{Datadir: testDirectory + "/data"})
	return result
}

func CreateTestBBoltStore(filePath string) (KVStore, error) {
	return createBBoltStore(filePath, &bbolt.Options{NoSync: true, NoFreelistSync: true, NoGrowSync: true})
}
