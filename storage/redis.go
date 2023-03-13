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
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/go-redis/redis/v9"
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/go-stoabs/redis7"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/storage/log"
	"github.com/sirupsen/logrus"
)

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
	Address  string              `koanf:"address"`
	Username string              `koanf:"username"`
	Password string              `koanf:"password"`
	Database string              `koanf:"database"`
	TLS      RedisTLSConfig      `koanf:"tls"`
	Sentinel RedisSentinelConfig `koanf:"sentinel"`
}

// isConfigured returns true if config the indicates Redis support should be enabled.
func (r RedisConfig) isConfigured() bool {
	return len(r.Address) > 0
}

func (r RedisConfig) parse() (*redis.Options, error) {
	// Backwards compatibility: if not an address URL, assume simply TCP with host:port
	addr := r.Address
	if !isRedisURL(addr) {
		addr = "redis://" + addr
	}

	opts, err := redis.ParseURL(addr)
	if err != nil {
		return nil, err
	}

	// Setup user/password auth
	if len(r.Username) > 0 {
		opts.Username = r.Username
	}
	if len(r.Password) > 0 {
		opts.Password = r.Password
	}

	// Setup TLS
	if len(r.TLS.TrustStoreFile) > 0 {
		if opts.TLSConfig == nil {
			return nil, errors.New("TLS configured but not connecting to a Redis TLS server")
		}
		trustStore, err := core.LoadTrustStore(r.TLS.TrustStoreFile)
		if err != nil {
			return nil, fmt.Errorf("unable to load truststore for Redis database: %w", err)
		}
		opts.TLSConfig.RootCAs = trustStore.CertPool
	}
	redisTLSModifier(opts.TLSConfig)
	return opts, nil
}

// RedisSentinelConfig specifies properties for connecting to a Redis Sentinel cluster.
type RedisSentinelConfig struct {
	Master   string   `koanf:"master"`
	Nodes    []string `koanf:"nodes"`
	Username string   `koanf:"username"`
	Password string   `koanf:"password"`
}

func (r RedisSentinelConfig) enabled() bool {
	return r.Master != "" || len(r.Nodes) > 0
}

// parse build redis.FailoverOptions from the given base options (which are copied) and the Sentinel-specific configuration.
func (r RedisSentinelConfig) parse(baseOpts redis.Options) (*redis.FailoverOptions, error) {
	// Master and node addresses are required options
	if r.Master == "" {
		return nil, errors.New("master is not configured")
	}
	if len(r.Nodes) == 0 {
		return nil, errors.New("node addresses are not configured")
	}

	var tlsConfig *tls.Config
	if baseOpts.TLSConfig != nil {
		tlsConfig = baseOpts.TLSConfig.Clone() // avoid mutating passed struct
		// Make tls.Config.ServerName empty, since otherwise it will pin a single server name, but sentinel clients will connect to any/multiple.
		tlsConfig.ServerName = ""
	}

	return &redis.FailoverOptions{
		// Sentinel-specific options
		MasterName:       r.Master,
		SentinelAddrs:    r.Nodes,
		SentinelUsername: r.Username,
		SentinelPassword: r.Password,
		// Generic options
		Username:        baseOpts.Username,
		Password:        baseOpts.Password,
		DB:              baseOpts.DB,
		MaxRetries:      baseOpts.MaxRetries,
		MinRetryBackoff: baseOpts.MinRetryBackoff,
		MaxRetryBackoff: baseOpts.MaxRetryBackoff,
		DialTimeout:     baseOpts.DialTimeout,
		ReadTimeout:     baseOpts.ReadTimeout,
		WriteTimeout:    baseOpts.WriteTimeout,
		PoolFIFO:        baseOpts.PoolFIFO,
		PoolSize:        baseOpts.PoolSize,
		PoolTimeout:     baseOpts.PoolTimeout,
		MinIdleConns:    baseOpts.MinIdleConns,
		MaxIdleConns:    baseOpts.MaxIdleConns,
		ConnMaxIdleTime: baseOpts.ConnMaxIdleTime,
		ConnMaxLifetime: baseOpts.ConnMaxLifetime,
		TLSConfig:       tlsConfig,
	}, nil
}

// RedisTLSConfig specifies properties for connecting to a Redis server over TLS.
type RedisTLSConfig struct {
	TrustStoreFile string `koanf:"truststorefile"`
}

func createRedisDatabase(config RedisConfig) (*redisDatabase, error) {
	opts, err := config.parse()
	if err != nil {
		return nil, err
	}
	// Configure Sentinel if enabled
	if config.Sentinel.enabled() {
		sentinelOpts, err := config.Sentinel.parse(*opts)
		if err != nil {
			return nil, fmt.Errorf("unable to configure Redis Sentinel client: %w", err)
		}
		return &redisDatabase{
			sentinelOptions: sentinelOpts,
			databaseName:    config.Database,
		}, nil
	}
	// Otherwise, regular Redis client
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

// redisLogWriter is a wrapper to redirect redis log to our logger
type redisLogWriter struct {
	logger *logrus.Entry
}

// Printf expects entries in the form:
// redis: sentinel.go:628: sentinel: new master="mymaster" addr="172.20.0.4:6379"
// All logs are written as Warning
func (t redisLogWriter) Printf(_ context.Context, format string, v ...interface{}) {
	t.logger.Warnf(format, v...)
}
