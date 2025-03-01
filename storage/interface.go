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
	"time"

	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/nuts-node/core"
	"gorm.io/gorm"
)

const lockAcquireTimeout = time.Second

// Engine defines the interface for the storage engine.
type Engine interface {
	core.Engine
	core.Configurable
	core.Runnable

	// GetProvider returns the Provider for the given module.
	GetProvider(moduleName string) Provider
	// GetSessionDatabase returns the SessionDatabase
	GetSessionDatabase() SessionDatabase

	// GetSQLDatabase returns the SQL database.
	GetSQLDatabase() *gorm.DB
}

// Provider lets callers get access to stores.
type Provider interface {
	// GetKVStore returns a key-value store. Stores are identified by a name.
	// When identical name is passed the same store is returned.
	// Names must be alphanumeric, non-zero strings.
	GetKVStore(name string, class Class) (stoabs.KVStore, error)
}

// Class defines levels of storage reliability.
type Class int

const (
	// VolatileStorageClass means losing the storage has no/little implications due to data loss (e.g. caches).
	VolatileStorageClass Class = iota
	// PersistentStorageClass means losing the storage should never happen, because it has major implications.
	PersistentStorageClass = iota
)

type database interface {
	createStore(moduleName string, storeName string) (stoabs.KVStore, error)
	getClass() Class
	close()
}

var ErrNotFound = errors.New("not found")

// SessionDatabase is a non-persistent database that holds session data on a KV basis.
// Keys could be access tokens, nonce's, authorization codes, etc.
// All entries are stored with a TTL, so they will be removed automatically.
type SessionDatabase interface {
	// GetStore returns a SessionStore with the given keys as key prefixes.
	// The keys are used to logically partition the store, eg: tenants and/or flows that are not allowed to overlap like credential issuance and verification.
	// The TTL is the time-to-live for the entries in the store.
	GetStore(ttl time.Duration, keys ...string) SessionStore
	// getFullKey returns the full key for the given key and prefixes.
	// the supported chars differ per backend.
	getFullKey(prefixes []string, key string) string
	// Close stops any background processes and closes the database.
	Close()
}

// SessionStore is a key-value store that holds session data.
// The SessionStore is an abstraction for underlying storage, it automatically adds prefixes for logical partitions.
type SessionStore interface {
	// Delete deletes the entry for the given key.
	// It does not return an error if the key does not exist.
	Delete(key string) error
	// Exists returns true if the key exists.
	Exists(key string) bool
	// Get returns the value for the given key.
	// Returns ErrNotFound if the key does not exist.
	Get(key string, target interface{}) error
	// Put stores the given value for the given key.
	// options can be used to fine-tune the storage of the item.
	Put(key string, value interface{}, options ...SessionOption) error
	// GetAndDelete combines Get and Delete as a convenience for burning nonce entries.
	GetAndDelete(key string, target interface{}) error
}

// TransactionKey is the key used to store the SQL transaction in the context.
type TransactionKey struct{}

// SessionOption is an option that can be given when storing items.
type SessionOption func(target *sessionOptions)

type sessionOptions struct {
	ttl time.Duration
}

// WithTTL sets the time-to-live for the stored item.
func WithTTL(ttl time.Duration) SessionOption {
	return func(target *sessionOptions) {
		target.ttl = ttl
	}
}
