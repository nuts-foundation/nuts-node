package tree

import (
	"encoding/binary"
	"fmt"
	"go.etcd.io/bbolt"
	"os"
	"path"

	"github.com/nuts-foundation/nuts-node/core"
)

type Store interface {
	Read(bucketName string, tree Tree) error
	Update(bucketName string, tree Tree) error
}

const (
	ibltBucketName = "treeIBLT"
	xorBucketName  = "treeXOR"
)

type bboltStore struct {
	db *bbolt.DB
}

// NewBBoltStore returns an instance of a BBolt based tree store
func NewBBoltStore() Store {
	return &bboltStore{}
}

func (store *bboltStore) Configure(config core.ServerConfig) error {
	var err error
	filePath := path.Join(config.Datadir, "network", "v2", "treestore.db")
	if err = os.MkdirAll(path.Join(config.Datadir, "network", "v2"), os.ModePerm); err != nil {
		return err
	}
	fmt.Println(*bbolt.DefaultOptions)
	options := &bbolt.Options{
		Timeout:      1,
		NoGrowSync:   false,
		FreelistType: bbolt.FreelistArrayType, // TODO: check this
	}
	store.db, err = bbolt.Open(filePath, 0600, options)

	return err
}

func (store *bboltStore) Start() error {
	// already done in Configure
	return nil
}

func (store *bboltStore) Shutdown() error {
	if store.db != nil {
		return store.db.Close()
	}
	return nil
}

func (store bboltStore) Read(bucketName string, tree Tree) error {
	return store.db.View(func(tx *bbolt.Tx) error {
		// get bucket
		bucket := tx.Bucket([]byte(bucketName))
		if bucket == nil {
			return fmt.Errorf("bucket '%q' not found", bucketName)
		}

		// get data
		rawData := map[uint32][]byte{}
		_ = bucket.ForEach(func(k, v []byte) error {
			split := binary.LittleEndian.Uint32(k)
			rawData[split] = v
			return nil
		})

		// build tree
		return tree.Load(rawData)
	})
}

func (store bboltStore) Update(bucketName string, tree Tree) error {
	return store.db.Update(func(tx *bbolt.Tx) error {
		dirties, orphaned, err := tree.GetUpdate()
		if err != nil {
			return err
		}
		tx.OnCommit(tree.ResetUpdate)

		bucket, err := tx.CreateBucketIfNotExists([]byte(bucketName))
		if err != nil {
			return err
		}

		// delete orphaned leafs
		key := make([]byte, 4)
		for _, orphan := range orphaned {
			binary.LittleEndian.PutUint32(key, orphan)
			err = bucket.Delete(key)
			if err != nil {
				return err
			}
		}

		// write new/updated leaves
		for dirty, data := range dirties {
			binary.LittleEndian.PutUint32(key, dirty)
			err = bucket.Put(key, data)
			if err != nil {
				return err
			}
		}
		return nil
	})
}
