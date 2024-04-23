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
	"context"
	"encoding/json"
	"errors"
	"github.com/nuts-foundation/go-stoabs"
	"strings"
	"time"
)

func NewRedisSessionDatabase(db stoabs.KVStore) SessionDatabase {
	result := redisSessionDatabase{
		db: db,
	}
	result.ctx, result.cancel = context.WithCancel(context.Background())
	return result
}

type redisSessionDatabase struct {
	db     stoabs.KVStore
	ctx    context.Context
	cancel context.CancelFunc
}

func (s redisSessionDatabase) GetStore(ttl time.Duration, keys ...string) SessionStore {
	return redisSessionStore{
		db:        s.db,
		ttl:       ttl,
		storeName: strings.Join(keys, "."),
	}
}

func (s redisSessionDatabase) close() {
	err := s.db.Close(s.ctx)
	if err != nil {
		return
	}
	s.cancel()
}

type redisSessionStore struct {
	db        stoabs.KVStore
	ttl       time.Duration
	storeName string
}

func (s redisSessionStore) Delete(key string) error {
	return s.db.WriteShelf(context.Background(), s.storeName, func(writer stoabs.Writer) error {
		return writer.Delete(stoabs.BytesKey(key))
	})
}

func (s redisSessionStore) Exists(key string) bool {
	err := s.db.ReadShelf(context.Background(), s.storeName, func(reader stoabs.Reader) error {
		_, err := reader.Get(stoabs.BytesKey(key))
		return err
	})
	if errors.Is(err, stoabs.ErrKeyNotFound) {
		return false
	}
	return true
}

func (s redisSessionStore) Get(key string, target interface{}) error {
	return s.db.ReadShelf(context.Background(), s.storeName, func(reader stoabs.Reader) error {
		data, err := reader.Get(stoabs.BytesKey(key))
		if err != nil {
			if errors.Is(err, stoabs.ErrKeyNotFound) {
				return ErrNotFound
			}
			return err
		}
		return json.Unmarshal(data, target)
	})
}

func (s redisSessionStore) Put(key string, value interface{}) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return s.db.WriteShelf(context.Background(), s.storeName, func(writer stoabs.Writer) error {
		tl, ok := writer.(stoabs.WriterTTl)
		if !ok {
			return writer.Put(stoabs.BytesKey(key), data)
		}
		return tl.PutTTL(stoabs.BytesKey(key), data, s.ttl)
	})

}
