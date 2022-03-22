package dag

import (
	"encoding/binary"
	"fmt"
	"github.com/nuts-foundation/nuts-node/network/dag/tree"
	"go.etcd.io/bbolt"
)

const (
	ibltBucketName = "treeIBLT"
	xorBucketName  = "treeXOR"
	// BucketFillPercent can be much higher than default 0.5 since the keys (unique node ids)
	// should be added to the bucket in monotonic increasing order, and the values are of fixed size.
	BucketFillPercent = 0.9
)

type bboltTree struct {
	db *bbolt.DB
}

// NewBBoltTreeStore returns an instance of a BBolt based tree store. Buckets managed by this store are filled to BucketFillPercent
func NewBBoltTreeStore(db *bbolt.DB) *bboltTree {
	return &bboltTree{db: db}
}

// Read fills the tree with data in the bucket.
// Returns an error the bucket does not exist, or if data in the bucket doesn't match the prototype.
func (store bboltTree) Read(bucketName string, prototype tree.Data) (tree.Tree, error) {
	tr := tree.New(prototype.New(), 0)
	return tr, store.db.View(func(tx *bbolt.Tx) error {
		// get bucket
		bucket := tx.Bucket([]byte(bucketName))
		if bucket == nil {
			return fmt.Errorf("bucket '%s' not found", bucketName)
		}

		// get data
		rawData := map[uint32][]byte{}
		_ = bucket.ForEach(func(k, v []byte) error {
			split := binary.LittleEndian.Uint32(k)
			rawData[split] = v
			return nil
		})

		// build tree
		return tr.Load(rawData)
	})
}

// Update writes an incremental update to the bucket.
// The incremental update is defined as changes to the tree since the last call to Tree.ResetUpdate,
// which is called when Update completes successfully.
func (store bboltTree) Update(bucketName string, tree tree.Tree) error {
	return store.db.Update(func(tx *bbolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte(bucketName))
		if err != nil {
			return err
		}
		bucket.FillPercent = BucketFillPercent

		// get data
		dirties, orphaned, err := tree.GetUpdates()
		if err != nil {
			return err
		}
		tx.OnCommit(tree.ResetUpdate)

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
