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
	"github.com/eko/gocache/lib/v4/cache"
	"github.com/eko/gocache/store/go_cache/v4"
	gocacheclient "github.com/patrickmn/go-cache"
	"strings"
	"time"
)

var _ SessionDatabase = (*InMemorySessionDatabase)(nil)

var sessionStorePruneInterval = 10 * time.Minute

// InMemorySessionDatabase is an in memory database that holds session data on a KV basis.
// Keys could be access tokens, nonce's, authorization codes, etc.
// All entries are stored with a TTL, so they will be removed automatically.
type InMemorySessionDatabase struct {
	underlying *cache.Cache[[]byte]
}

// NewInMemorySessionDatabase creates a new in memory session database.
func NewInMemorySessionDatabase() *InMemorySessionDatabase {
	gocacheClient := gocacheclient.New(5*time.Minute, sessionStorePruneInterval)
	gocacheStore := go_cache.NewGoCache(gocacheClient)
	return &InMemorySessionDatabase{
		underlying: cache.New[[]byte](gocacheStore),
	}
}

func (s *InMemorySessionDatabase) GetStore(ttl time.Duration, keys ...string) SessionStore {
	return SessionStoreImpl[[]byte]{
		underlying: s.underlying,
		ttl:        ttl,
		prefixes:   keys,
		db:         s,
	}
}

func (s *InMemorySessionDatabase) close() {
	// NOP
}

func (s *InMemorySessionDatabase) getFullKey(prefixes []string, key string) string {
	return strings.Join(append(prefixes, key), "/")
}
