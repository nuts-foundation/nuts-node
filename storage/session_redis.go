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
	"github.com/nuts-foundation/nuts-node/storage/log"
	"github.com/redis/go-redis/v9"
	"strings"
	"time"
)

func NewRedisSessionDatabase(client RedisClient) SessionDatabase {
	return redisSessionDatabase{
		client: client.Client,
		prefix: client.Prefix,
	}
}

type redisSessionDatabase struct {
	client *redis.Client
	prefix string
}

func (s redisSessionDatabase) GetStore(ttl time.Duration, keys ...string) SessionStore {
	var prefixParts []string
	if len(s.prefix) > 0 {
		prefixParts = append(prefixParts, s.prefix)
	}
	for i := range keys {
		prefixParts = append(prefixParts, keys[i])
	}
	return redisSessionStore{
		client:    s.client,
		ttl:       ttl,
		storeName: strings.Join(prefixParts, "."),
	}
}

func (s redisSessionDatabase) close() {
	err := s.client.Close()
	if err != nil {
		log.Logger().WithError(err).Error("Failed to close redis client")
	}
}

type redisSessionStore struct {
	client    *redis.Client
	ttl       time.Duration
	storeName string
}

func (s redisSessionStore) Delete(key string) error {
	err := s.client.Del(context.Background(), s.toRedisKey(key)).Err()
	if err != nil {
		return err
	}
	return nil
}

func (s redisSessionStore) Exists(key string) bool {
	result, err := s.client.Exists(context.Background(), s.toRedisKey(key)).Result()
	if err != nil {
		return false
	}
	return result > 0
}

func (s redisSessionStore) Get(key string, target interface{}) error {
	result, err := s.client.Get(context.Background(), s.toRedisKey(key)).Result()
	if err != nil {
		if errors.Is(redis.Nil, err) {
			return ErrNotFound
		}
		return err
	}
	return json.Unmarshal([]byte(result), target)
}

func (s redisSessionStore) Put(key string, value interface{}) error {
	marshal, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return s.client.Set(context.Background(), s.toRedisKey(key), marshal, s.ttl).Err()

}

func (s redisSessionStore) toRedisKey(key string) string {
	if len(s.storeName) > 0 {
		return strings.Join([]string{s.storeName, key}, ".")
	}
	return key
}
