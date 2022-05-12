package storage

import (
	"errors"
	"github.com/nuts-foundation/nuts-node/core"
)

// ErrCommitFailed is returned when the commit of transaction fails.
var ErrCommitFailed = errors.New("unable to commit transaction")

// Engine defines the interface for the storage engine.
type Engine interface {
	core.Engine
	core.Configurable
	core.Runnable
	Warehouse
}

// Warehouse is used to manage data stores.
type Warehouse interface {
	// GetKVStore returns a key-value store for the given engine and store name.
	GetKVStore(engineKey string, storeName string) (KVStore, error)
}

// KVStore defines the interface for a key-value store.
// Writing to it is done in callbacks passed to the Write-functions. If the callback returns an error, the transaction is rolled back.
type KVStore interface {
	// Close releases all resources associated with the KVStore. It is safe to call multiple (subsequent) times.
	Close() error
	// Write starts a writable transaction and passes it to the given function.
	Write(fn func(WriteTransaction) error) error
	// Read starts a read-only transaction and passes it to the given function.
	Read(fn func(transaction ReadTransaction) error) error
	// WriteBucket starts a writable transaction, retrieves the specified bucket and passes it to the given function.
	// If the bucket does not exist, it will be created.
	WriteBucket(bucketName string, fn func(BucketWriter) error) error
	// ReadBucket starts a read-only transaction, retrieves the specified bucket and passes it to the given function.
	// If the bucket does not exist, the function is not called.
	ReadBucket(bucketName string, fn func(BucketReader) error) error
}

// WriteTransaction is used to write to a KVStore.
type WriteTransaction interface {
	// Bucket returns the specified bucket for writing. If it doesn't exist, it will be created.
	Bucket(bucketName string) (BucketWriter, error)
}

// ReadTransaction is used to read from a KVStore.
type ReadTransaction interface {
	// Bucket returns the specified bucket for reading. If it doesn't exist, nil is returned.
	Bucket(bucketName string) (BucketReader, error)
}

// BucketStats contains statistics about a bucket.
type BucketStats struct {
	// NumEntries holds the number of entries in the bucket.
	NumEntries uint
}

// BucketReader is used to read from a bucket.
type BucketReader interface {
	// Get returns the value for the given key. If it does not exist it returns nil.
	Get(key []byte) ([]byte, error)
	// Cursor returns a cursor for iterating over the bucket.
	Cursor() (Cursor, error)
	// Stats returns statistics about the bucket.
	Stats() BucketStats
}

// BucketWriter is used to write to a bucket.
type BucketWriter interface {
	BucketReader

	// Put stores the given key and value in the bucket.
	Put(key []byte, value []byte) error
	// Delete removes the given key from the bucket.
	Delete(key []byte) error
}

// Cursor defines the API for iterating over data in a bucket.
type Cursor interface {
	// Seek moves the cursor to the specified key.
	Seek(seek []byte) (key []byte, value []byte)
	// Next moves the cursor to the next key.
	Next() (key []byte, value []byte)
}
