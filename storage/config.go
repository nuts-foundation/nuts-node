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
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 */

package storage

import "time"

// Config specifies config for the storage engine.
type Config struct {
	BBolt   BBoltConfig   `koanf:"bbolt"`
	Redis   RedisConfig   `koanf:"redis"`
	SQL     SQLConfig     `koanf:"sql"`
	KV      KVConfig      `koanf:"kv"`
	Session SessionConfig `koanf:"session"`
	// Debug specifies whether to enable debug logging for the storage engine, e.g. performance metrics and query logging.
	Debug bool `koanf:"debug"`
}

// KVConfig specifies which backend holds the key-value stores used by the did:nuts stack
// (network DAG, did:nuts DID store, credential backup shelves).
type KVConfig struct {
	// Backend is the key-value store backend: KVBackendBBolt (default) or KVBackendSQL.
	Backend string `koanf:"backend"`
}

const (
	// KVBackendBBolt stores the key-value stores in bbolt files in the data directory. Allows a single node instance.
	KVBackendBBolt = "bbolt"
	// KVBackendSQL stores the key-value stores in the SQL database configured through storage.sql.connection.
	KVBackendSQL = "sql"
)

// DefaultConfig returns the default configuration for the module.
func DefaultConfig() Config {
	return Config{
		SQL: SQLConfig{
			RDSIAM: RDSIAMConfig{
				TokenRefreshInterval: 14 * time.Minute,
			},
		},
		BBolt: BBoltConfig{
			LockTimeout: time.Second,
		},
		KV: KVConfig{
			Backend: KVBackendBBolt,
		},
	}
}

// SQLConfig specifies config for the SQL storage engine.
type SQLConfig struct {
	// ConnectionString is the connection string for the SQL database.
	// This string may contain secrets (user:password), so should never be logged.
	ConnectionString string `koanf:"connection"`
	// RDSIAM specifies AWS RDS IAM authentication configuration.
	RDSIAM RDSIAMConfig `koanf:"rdsiam"`
}

// RDSIAMConfig specifies config for AWS RDS IAM authentication.
type RDSIAMConfig struct {
	// Enabled determines whether to use AWS IAM authentication for RDS.
	Enabled bool `koanf:"enabled"`
	// Region is the AWS region where the RDS instance is located.
	// If not specified, it will be loaded from the AWS SDK default configuration.
	Region string `koanf:"region"`
	// DBUser is the database user for IAM authentication.
	// If not specified, the user from the connection string will be used.
	DBUser string `koanf:"dbuser"`
	// TokenRefreshInterval is how often to refresh the IAM token (default: 14 minutes).
	// RDS tokens are valid for 15 minutes, so we refresh before expiry.
	TokenRefreshInterval time.Duration `koanf:"tokenrefreshinterval"`
}

// SessionConfig specifies config for the session storage engine.
type SessionConfig struct {
	// Memcached specifies config for the Memcached session storage engine.
	Memcached MemcachedConfig `koanf:"memcached"`
	// Redis specifies config for the Redis session storage engine.
	Redis RedisConfig `koanf:"redis"`
}
