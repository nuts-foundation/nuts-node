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
	"net/url"
	"path"
	"strings"
)

const sentinelMasterNameParam = "sentinelMasterName"
const sentinelUsernameParam = "sentinelUsername"
const sentinelPasswordParam = "sentinelPassword"

var sentinelParamKeys = []string{sentinelMasterNameParam, sentinelUsernameParam, sentinelPasswordParam}

var redisTLSModifier = func(conf *tls.Config) {
	// do nothing by default, used for testing
}

type redisDatabase struct {
	databaseName    string
	options         *redis.Options
	sentinelOptions *redis.FailoverOptions
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

// RedisTLSConfig specifies properties for connecting to a Redis server over TLS.
type RedisTLSConfig struct {
	TrustStoreFile string `koanf:"truststorefile"`
}

func createRedisDatabase(config RedisConfig) (*redisDatabase, error) {
	// Backwards compatibility: if not an address URL, assume simply TCP with host:port
	if !isRedisURL(config.Address) {
		config.Address = "redis://" + config.Address
	}

	// Redis Sentinel support: if sentinelMasterName is present in the connection URL, crete a Sentinel client.
	sentinelOptions, err := parseRedisSentinelURL(config)
	if err != nil {
		return nil, fmt.Errorf("unable to configure Redis Sentinel client: %w", err)
	}
	if sentinelOptions != nil {
		return &redisDatabase{
			sentinelOptions: sentinelOptions,
			databaseName:    config.Database,
		}, nil
	}

	// Regular Redis client
	opts, err := parseRedisConfig(config)
	if err != nil {
		return nil, err
	}
	return &redisDatabase{
		options:      opts,
		databaseName: config.Database,
	}, nil
}

// parseRedisSentinelURL parses connectionString as URL to see if Redis Sentinel support must be enabled.
// If so, it returns true, the parsed URL without Sentinel options (because otherwise redis.ParseURL() would fail later on),
// If the connectionString doesn't specify Redis Sentinel options, it returns false.
func parseRedisSentinelURL(config RedisConfig) (*redis.FailoverOptions, error) {
	//uriString := "redis://host1:1234,host2:4321?sentinelMasterName=bla"
	// Errors return by url.Parse() are ignored, because they only happen in edge, extremely edge situations.
	// We just return from the function, and the error occurs and gets captured again when using redis.ParseURL().
	sentinelURI, _ := url.Parse(config.Address)
	if sentinelURI == nil {
		return nil, nil
	}
	masterName := sentinelURI.Query().Get(sentinelMasterNameParam)
	if len(masterName) == 0 {
		// Sentinel not enabled
		return nil, nil
	}

	// Parse Redis options without Sentinel options, because they are unofficial
	redisURI := *sentinelURI
	newQuery := sentinelURI.Query()
	for _, key := range sentinelParamKeys {
		newQuery.Del(key)
	}
	redisURI.RawQuery = newQuery.Encode()
	config.Address = redisURI.String()
	opts, err := parseRedisConfig(config)
	if err != nil {
		return nil, err
	}

	// Parse Sentinel addresses
	sentinelAddrs := strings.Split(sentinelURI.Host, ",")

	// Make tls.Config.ServerName empty if set, since otherwise it will pin a single server name, but sentinel will connect to any/multiple.
	if opts.TLSConfig != nil {
		opts.TLSConfig.ServerName = ""
	}

	return &redis.FailoverOptions{
		MasterName:       masterName,
		SentinelAddrs:    sentinelAddrs,
		SentinelUsername: sentinelURI.Query().Get(sentinelUsernameParam),
		SentinelPassword: sentinelURI.Query().Get(sentinelPasswordParam),
		Username:         opts.Username,
		Password:         opts.Password,
		DB:               opts.DB,
		MaxRetries:       opts.MaxRetries,
		MinRetryBackoff:  opts.MinRetryBackoff,
		MaxRetryBackoff:  opts.MaxRetryBackoff,
		DialTimeout:      opts.DialTimeout,
		ReadTimeout:      opts.ReadTimeout,
		WriteTimeout:     opts.WriteTimeout,
		PoolFIFO:         opts.PoolFIFO,
		PoolSize:         opts.PoolSize,
		PoolTimeout:      opts.PoolTimeout,
		MinIdleConns:     opts.MinIdleConns,
		MaxIdleConns:     opts.MaxIdleConns,
		ConnMaxIdleTime:  opts.ConnMaxIdleTime,
		ConnMaxLifetime:  opts.ConnMaxLifetime,
		TLSConfig:        opts.TLSConfig,
	}, nil
}

func isRedisURL(address string) bool {
	return strings.HasPrefix(address, "redis://") ||
		strings.HasPrefix(address, "rediss://") ||
		strings.HasPrefix(address, "unix://")
}

func parseRedisConfig(config RedisConfig) (*redis.Options, error) {
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
	return opts, nil
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
	opts := stoabs.WithLockAcquireTimeout(lockAcquireTimeout)
	if b.sentinelOptions != nil {
		return redis7.Wrap(prefix, redis.NewFailoverClient(b.sentinelOptions), opts)
	}
	return redis7.CreateRedisStore(prefix, b.options, opts)
}

func (b redisDatabase) getClass() Class {
	return PersistentStorageClass
}

func (b redisDatabase) close() {
	// Nothing to do
}
