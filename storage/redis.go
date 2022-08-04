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
	"github.com/go-redis/redis/v9"
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/go-stoabs/redis7"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/storage/log"
	"path"
	"strings"
)

type redisDatabase struct {
	databaseName string
	options      *redis.Options
}

// RedisConfig specifies config for Redis databases.
type RedisConfig struct {
	Address  string `koanf:"address"`
	Username string `koanf:"username"`
	Password string `koanf:"password"`
	Database string `koanf:"database"`
}

// IsConfigured returns true if config the indicates Redis support should be enabled.
func (r RedisConfig) IsConfigured() bool {
	return len(r.Address) > 0
}

func createRedisDatabase(config RedisConfig) (*redisDatabase, error) {
	result := redisDatabase{
		options: &redis.Options{
			Addr:     config.Address,
			Username: config.Username,
			Password: config.Password,
		},
		databaseName: config.Database,
	}
	return &result, nil
}

func (b redisDatabase) createStore(moduleName string, storeName string) (stoabs.KVStore, error) {
	log.Logger().
		WithField(core.LogFieldStore, path.Join(moduleName, storeName)).
		Debug("Creating Redis store")
	var prefixParts []string
	if len(b.databaseName) > 0 {
		prefixParts = append(prefixParts, b.databaseName)
	}
	prefixParts = append(prefixParts, moduleName)
	prefixParts = append(prefixParts, storeName)
	prefix := strings.ToLower(strings.Join(prefixParts, "_"))
	return redis7.CreateRedisStore(prefix, b.options, stoabs.WithLockAcquireTimeout(lockAcquireTimeout))
}

func (b redisDatabase) getClass() Class {
	return PersistentStorageClass
}

func (b redisDatabase) close() {
	// Nothing to do
}
