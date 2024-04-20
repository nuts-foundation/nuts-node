/*
 * Copyright (C) 2023 Nuts community
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
	"encoding/json"
	"github.com/nuts-foundation/nuts-node/storage/log"
	"strings"
	"sync"
	"time"
)

var sessionStorePruneInterval = 10 * time.Minute

var _ SessionDatabase = (*InMemorySessionDatabase)(nil)
var _ SessionStore = (*InMemorySessionStore)(nil)

type expiringEntry struct {
	// Value stores the actual value as JSON
	Value  string
	Expiry time.Time
}

// InMemorySessionDatabase is an in memory database that holds session data on a KV basis.
// Keys could be access tokens, nonce's, authorization codes, etc.
// All entries are stored with a TTL, so they will be removed automatically.
type InMemorySessionDatabase struct {
	done     chan struct{}
	mux      sync.RWMutex
	routines sync.WaitGroup
	entries  map[string]expiringEntry
}

// NewInMemorySessionDatabase creates a new in memory session database.
func NewInMemorySessionDatabase() *InMemorySessionDatabase {
	result := &InMemorySessionDatabase{
		entries: map[string]expiringEntry{},
		done:    make(chan struct{}, 10),
	}
	result.startPruning(sessionStorePruneInterval)
	return result
}

func (i *InMemorySessionDatabase) GetStore(ttl time.Duration, keys ...string) SessionStore {
	return InMemorySessionStore{
		ttl:      ttl,
		prefixes: keys,
		db:       i,
	}
}

func (i *InMemorySessionDatabase) close() {
	// Signal pruner to stop and wait for it to finish
	i.done <- struct{}{}
}

func (i *InMemorySessionDatabase) startPruning(interval time.Duration) {
	ticker := time.NewTicker(interval)
	i.routines.Add(1)
	go func() {
		defer i.routines.Done()
		for {
			select {
			case <-i.done:
				ticker.Stop()
				return
			case <-ticker.C:
				valsPruned := i.prune()
				if valsPruned > 0 {
					log.Logger().Debugf("Pruned %d expired session variables", valsPruned)
				}
			}
		}
	}()
}

func (i *InMemorySessionDatabase) prune() int {
	i.mux.Lock()
	defer i.mux.Unlock()

	moment := time.Now()

	// Find expired flows and delete them
	var count int
	for key, entry := range i.entries {
		if entry.Expiry.Before(moment) {
			count++
			delete(i.entries, key)
		}
	}

	return count
}

type InMemorySessionStore struct {
	ttl      time.Duration
	prefixes []string
	db       *InMemorySessionDatabase
}

func (i InMemorySessionStore) Delete(key string) error {
	i.db.mux.Lock()
	defer i.db.mux.Unlock()

	delete(i.db.entries, i.getFullKey(key))
	return nil
}

func (i InMemorySessionStore) Exists(key string) bool {
	i.db.mux.Lock()
	defer i.db.mux.Unlock()

	_, ok := i.db.entries[i.getFullKey(key)]
	return ok
}

func (i InMemorySessionStore) Get(key string, target interface{}) error {
	i.db.mux.Lock()
	defer i.db.mux.Unlock()

	fullKey := i.getFullKey(key)
	entry, ok := i.db.entries[fullKey]
	if !ok {
		return ErrNotFound
	}
	if entry.Expiry.Before(time.Now()) {
		delete(i.db.entries, fullKey)
		return ErrNotFound
	}

	return json.Unmarshal([]byte(entry.Value), target)
}

func (i InMemorySessionStore) Put(key string, value interface{}) error {
	i.db.mux.Lock()
	defer i.db.mux.Unlock()

	bytes, err := json.Marshal(value)
	if err != nil {
		return err
	}
	entry := expiringEntry{
		Value:  string(bytes),
		Expiry: time.Now().Add(i.ttl),
	}

	i.db.entries[i.getFullKey(key)] = entry
	return nil
}

func (i InMemorySessionStore) getFullKey(key string) string {
	return strings.Join(append(i.prefixes, key), "/")
}
