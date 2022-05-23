/*
 * Copyright (C) 2022 Nuts community
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

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
	Provider
}

// Provider lets callers get access to stores.
type Provider interface {
	// GetKVStore returns a key-value store. Stores are created in a namespace identified by a name.
	// When identical namespace/name is passed the same store is returned.
	// Store names may appear in multiple namespaces.
	// Namespaces and names must be alphanumeric, non-zero strings.
	GetKVStore(namespace string, name string) (KVStore, error)
}

// KVStore defines the interface for a key-value store.
// Writing to it is done in callbacks passed to the Write-functions. If the callback returns an error, the transaction is rolled back.
type KVStore interface {
	// Close releases all resources associated with the KVStore. It is safe to call multiple (subsequent) times.
	Close() error
	// Write starts a writable transaction and passes it to the given function.
	Write(fn func(WriteTx) error, opts ...TxOption) error
	// Read starts a read-only transaction and passes it to the given function.
	Read(fn func(ReadTx) error) error
	// WriteBucket starts a writable transaction, retrieves the specified bucket and passes it to the given function.
	// If the bucket does not exist, it will be created.
	WriteBucket(bucketName string, fn func(BucketWriter) error) error
	// ReadBucket starts a read-only transaction, retrieves the specified bucket and passes it to the given function.
	// If the bucket does not exist, the function is not called.
	ReadBucket(bucketName string, fn func(BucketReader) error) error
}

// TxOption holds options for store transactions.
type TxOption interface{}

type afterCommit struct {
	fn func()
}

// AfterCommit specifies a function that will be called after a transaction is successfully committed.
// There can be multiple AfterCommit functions, which will be called in order.
func AfterCommit(fn func()) TxOption {
	return &afterCommit{fn: fn}
}

type afterRollback struct {
	fn func()
}

// AfterRollback specifies a function that will be called after a transaction is successfully rolled back.
// There can be multiple AfterRollback functions, which will be called in order.
func AfterRollback(fn func()) TxOption {
	return &afterRollback{fn: fn}
}

// WriteTx is used to write to a KVStore.
type WriteTx interface {
	// Bucket returns the specified bucket for writing. If it doesn't exist, it will be created.
	Bucket(bucketName string) (BucketWriter, error)
}

// ReadTx is used to read from a KVStore.
type ReadTx interface {
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
