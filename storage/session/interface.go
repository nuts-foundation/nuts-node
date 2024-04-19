package session

import (
	"errors"
	"time"
)

var ErrNotFound = errors.New("not found")

// SessionDatabase is a non-persistent database that holds session data on a KV basis.
// Keys could be access tokens, nonce's, authorization codes, etc.
// All entries are stored with a TTL, so they will be removed automatically.
type SessionDatabase interface {
	// GetStore returns a SessionStore with the given keys as key prefixes.
	// The keys are used to logically partition the store, eg: tenants and/or flows that are not allowed to overlap like credential issuance and verification.
	// The TTL is the time-to-live for the entries in the store.
	GetStore(ttl time.Duration, keys ...string) SessionStore
	// close stops any background processes and closes the database.
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
	Put(key string, value interface{}) error
}
