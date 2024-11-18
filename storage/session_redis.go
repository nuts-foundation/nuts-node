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

	"github.com/eko/gocache/lib/v4/cache"
	redisstore "github.com/eko/gocache/store/redis/v4"
	"github.com/redis/go-redis/v9"
)

type redisSessionDatabase struct {
	underlying *cache.Cache[string]
	prefix     string
	client     *redis.Client
}

func NewRedisSessionDatabase(client *redis.Client, prefix string) SessionDatabase {
	redisStore := redisstore.NewRedis(client)
	return redisSessionDatabase{
		underlying: cache.New[string](redisStore),
		prefix:     prefix,
		client:     client,
	}
}

func (s redisSessionDatabase) GetStore(ttl time.Duration, keys ...string) SessionStore {
	var prefixParts []string
	if len(s.prefix) > 0 {
		prefixParts = append(prefixParts, s.prefix)
	}
	prefixParts = append(prefixParts, keys...)
	return SessionStoreImpl[string]{
		underlying: s.underlying,
		ttl:        ttl,
		prefixes:   prefixParts,
		db:         s,
	}
}

func (s redisSessionDatabase) Close() {
	if s.client != nil {
		_ = s.client.Close()
	}
}

func (s redisSessionDatabase) getFullKey(prefixes []string, key string) string {
	return strings.Join(append(prefixes, key), ".")
}
