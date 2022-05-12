package storage

import (
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/network/log"
	"go.etcd.io/bbolt"
	"os"
	"path"
)

var _ KVStore = (*bboltStore)(nil)
var _ BucketWriter = (*bboltBucket)(nil)
var _ BucketReader = (*bboltBucket)(nil)
var _ ReadTransaction = (*bboltReadTransaction)(nil)
var _ WriteTransaction = (*bboltWriteTransaction)(nil)

//var _ Cursor = (*bboltCursor)(nil)

// CreateBBoltStore creates a new BBolt-backed KV store.
func CreateBBoltStore(filePath string) (KVStore, error) {
	return createBBoltStore(filePath, nil)
}

func createBBoltStore(filePath string, options *bbolt.Options) (KVStore, error) {
	err := os.MkdirAll(path.Dir(filePath), os.ModePerm) // TODO: Right permissions?
	if err != nil {
		return nil, err
	}
	db, err := bbolt.Open(filePath, os.FileMode(0640), options) // TODO: Right permissions?
	if err != nil {
		return nil, err
	}
	return &bboltStore{db: db}, nil
}

type bboltStore struct {
	db *bbolt.DB
}

func (b bboltStore) Write(fn func(WriteTransaction) error) error {
	return b.doTX(func(tx *bbolt.Tx) error {
		return fn(&bboltWriteTransaction{tx: tx})
	}, true)
}

func (b bboltStore) Read(fn func(transaction ReadTransaction) error) error {
	return b.doTX(func(tx *bbolt.Tx) error {
		return fn(&bboltReadTransaction{tx: tx})
	}, false)
}

func (b bboltStore) Close() error {
	return b.db.Close()
}

func (b bboltStore) WriteBucket(bucketName string, fn func(writer BucketWriter) error) error {
	return b.doTX(func(tx *bbolt.Tx) error {
		bucket, err := bboltWriteTransaction{tx: tx}.Bucket(bucketName)
		if err != nil {
			return err
		}
		return fn(bucket)
	}, true)
}

func (b bboltStore) ReadBucket(bucketName string, fn func(reader BucketReader) error) error {
	return b.doTX(func(tx *bbolt.Tx) error {
		bucket, err := bboltReadTransaction{tx: tx}.Bucket(bucketName)
		if err != nil {
			return err
		}
		if bucket == nil {
			return nil
		}
		return fn(bucket)
	}, false)
}

func (b bboltStore) doTX(fn func(tx *bbolt.Tx) error, writable bool) error {
	// Start transaction, retrieve/create bucket to operate on
	dbTX, err := b.db.Begin(writable)
	if err != nil {
		return err
	}

	// Perform TX action(s)
	appError := fn(dbTX)

	// Writable TXs should be committed, non-writable TXs rolled back
	if !writable {
		err := dbTX.Rollback()
		if err != nil {
			log.Logger().Errorf("Could not rollback BBolt transaction: %s", err)
		}
		return appError
	}
	// Observe result, commit/rollback
	if appError == nil {
		log.Logger().Tracef("Committing BBolt transaction")
		err := dbTX.Commit()
		if err != nil {
			return core.WrapError(ErrCommitFailed, err)
		}
	} else {
		log.Logger().Warnf("Rolling back transaction application due to error: %s", appError)
		err := dbTX.Rollback()
		if err != nil {
			log.Logger().Errorf("Could not rollback BBolt transaction: %s", err)
		}
		return appError
	}

	return nil
}

type bboltReadTransaction struct {
	tx *bbolt.Tx
}

func (b bboltReadTransaction) Bucket(bucketName string) (BucketReader, error) {
	bucket := b.tx.Bucket([]byte(bucketName))
	if bucket == nil {
		return nil, nil
	}
	return &bboltBucket{bucket: bucket}, nil
}

type bboltWriteTransaction struct {
	tx *bbolt.Tx
}

func (b bboltWriteTransaction) Bucket(bucketName string) (BucketWriter, error) {
	bucket, err := b.tx.CreateBucketIfNotExists([]byte(bucketName))
	if err != nil {
		return nil, err
	}
	return &bboltBucket{bucket: bucket}, nil
}

type bboltBucket struct {
	bucket *bbolt.Bucket
}

func (t bboltBucket) Cursor() (Cursor, error) {
	return t.bucket.Cursor(), nil
}

func (t bboltBucket) Get(key []byte) ([]byte, error) {
	value := t.bucket.Get(key)
	// Because things will go terribly wrong when you use a []byte returned by BBolt outside its transaction,
	// we want to make sure to work with a copy.
	//
	// This seems to be the best (and shortest) way to copy a byte slice:
	// https://github.com/go101/go101/wiki/How-to-perfectly-clone-a-slice%3F
	return append(value[:0:0], value...), nil
}

func (t bboltBucket) Put(key []byte, value []byte) error {
	return t.bucket.Put(key, value)
}

func (t bboltBucket) Delete(key []byte) error {
	return t.bucket.Delete(key)
}

func (t bboltBucket) Stats() BucketStats {
	return BucketStats{
		NumEntries: uint(t.bucket.Stats().KeyN),
	}
}
