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
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/go-redis/redis/v9"
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/go-stoabs/redis7"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/storage/log"
	"path"
	"strings"
)

var redisTLSModifier = func(conf *tls.Config) {
	// do nothing by default, used for testing
}

type redisDatabase struct {
	databaseName string
	options      *redis.Options
}

// RedisConfig specifies config for Redis databases.
type RedisConfig struct {
	Address  string         `koanf:"address"`
	Username string         `koanf:"username"`
	Password string         `koanf:"password"`
	Database string         `koanf:"database"`
	TLS      RedisTLSConfig `koanf:"tls"`
}

// IsConfigured returns true if config the indicates Redis support should be enabled.
func (r RedisConfig) IsConfigured() bool {
	return len(r.Address) > 0
}

// RedisTLSConfig species properties for connecting to a Redis server over TLS.
type RedisTLSConfig struct {
	TrustStoreFile string `koanf:"truststorefile"`
}

func createRedisDatabase(config RedisConfig) (*redisDatabase, error) {
	// Backwards compatibility: if not an address URL, assume simply TCP with host:port
	if !isRedisURL(config.Address) {
		config.Address = "redis://" + config.Address
	}
	opts, err := redis.ParseURL(config.Address)
	if err != nil {
		return nil, err
	}

	// Setup user/password auth
	if len(config.Username) > 0 {
		opts.Username = config.Username
	}
	if len(config.Password) > 0 {
		opts.Password = config.Password
	}

	// Setup TLS
	if len(config.TLS.TrustStoreFile) > 0 {
		if opts.TLSConfig == nil {
			return nil, errors.New("TLS configured but not connecting to a Redis TLS server")
		}
		trustStore, err := core.LoadTrustStore(config.TLS.TrustStoreFile)
		if err != nil {
			return nil, fmt.Errorf("unable to load truststore for Redis database: %w", err)
		}
		opts.TLSConfig.RootCAs = trustStore.CertPool
	}
	redisTLSModifier(opts.TLSConfig)

	return &redisDatabase{
		options:      opts,
		databaseName: config.Database,
	}, nil
}

func isRedisURL(address string) bool {
	return strings.HasPrefix(address, "redis://") ||
		strings.HasPrefix(address, "rediss://") ||
		strings.HasPrefix(address, "unix://")
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
