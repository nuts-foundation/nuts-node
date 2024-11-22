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
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/bradfitz/gomemcache/memcache"
	"github.com/eko/gocache/lib/v4/cache"
	"github.com/eko/gocache/lib/v4/store"
)

var _ SessionStore = (*SessionStoreImpl[[]byte])(nil)

// defaultSessionDataTTL is the default time to live for session data
// some stores require a default
var defaultSessionDataTTL = 15 * time.Minute

// StringOrBytes is a type that can be either a string or a byte slice
// used for generic type constraints
type StringOrBytes interface {
	~string | ~[]byte
}

// SessionStoreImpl is an implementation of the SessionStore interface
// It handles logic for all session store types
type SessionStoreImpl[T StringOrBytes] struct {
	underlying *cache.Cache[T]
	ttl        time.Duration
	prefixes   []string
	db         SessionDatabase
}

func (s SessionStoreImpl[T]) Delete(key string) error {
	err := s.underlying.Delete(context.Background(), s.db.getFullKey(s.prefixes, key))
	if err != nil {
		if errors.Is(err, store.NotFound{}) || errors.Is(err, memcache.ErrCacheMiss) {
			return nil
		}
		return err
	}
	return nil
}

func (s SessionStoreImpl[T]) Exists(key string) bool {
	val, err := s.underlying.Get(context.Background(), s.db.getFullKey(s.prefixes, key))
	if err != nil {
		return false
	}
	return len(val) > 0
}

func (s SessionStoreImpl[T]) Get(key string, target interface{}) error {
	val, err := s.underlying.Get(context.Background(), s.db.getFullKey(s.prefixes, key))
	if err != nil {
		// memcache.ErrCacheMiss is added here since the abstraction layer doesn't map this error to NotFound
		if errors.Is(err, store.NotFound{}) || errors.Is(err, memcache.ErrCacheMiss) {
			return ErrNotFound
		}
		return err
	}
	if len(val) == 0 {
		return ErrNotFound
	}

	return json.Unmarshal([]byte(val), target)
}

func (s SessionStoreImpl[T]) Put(key string, value interface{}) error {
	bytes, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return s.underlying.Set(context.Background(), s.db.getFullKey(s.prefixes, key), T(bytes), store.WithExpiration(s.ttl))
}
func (s SessionStoreImpl[T]) GetAndDelete(key string, target interface{}) error {
	if err := s.Get(key, target); err != nil {
		return err
	}
	return s.underlying.Delete(context.Background(), s.db.getFullKey(s.prefixes, key))
}
