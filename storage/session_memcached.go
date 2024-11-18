/*
 * Copyright (C) 2024 Nuts community
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
	"strings"
	"time"

	"github.com/bradfitz/gomemcache/memcache"
	"github.com/eko/gocache/lib/v4/cache"
	"github.com/eko/gocache/lib/v4/store"
	memcachestore "github.com/eko/gocache/store/memcache/v4"
)

type MemcachedSessionDatabase struct {
	client     *memcache.Client
	underlying *cache.Cache[[]byte]
}

// NewMemcachedSessionDatabase creates a new MemcachedSessionDatabase using an initialized memcache.Client.
func NewMemcachedSessionDatabase(client *memcache.Client) *MemcachedSessionDatabase {
	memcachedStore := memcachestore.NewMemcache(client, store.WithExpiration(defaultSessionDataTTL))
	return &MemcachedSessionDatabase{
		underlying: cache.New[[]byte](memcachedStore),
	}
}

func (s MemcachedSessionDatabase) GetStore(ttl time.Duration, keys ...string) SessionStore {
	return SessionStoreImpl[[]byte]{
		underlying: s.underlying,
		ttl:        ttl,
		prefixes:   keys,
		db:         s,
	}
}

func (s MemcachedSessionDatabase) close() {
	// noop
	if s.client != nil {
		_ = s.client.Close()
	}
}

func (s MemcachedSessionDatabase) getFullKey(prefixes []string, key string) string {
	return strings.Join(append(prefixes, key), "/")
}
