/*
 * Nuts node
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
 */

package cmd

import (
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/spf13/pflag"
	"strings"
)

// FlagSet contains flags relevant for the engine
func FlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("storage", pflag.ContinueOnError)
	defs := storage.DefaultConfig()
	flagSet.String("storage.bbolt.backup.directory", defs.BBolt.Backup.Directory, "Only used by did:nuts/gRPC. Target directory for BBolt database backups.")
	flagSet.Duration("storage.bbolt.backup.interval", defs.BBolt.Backup.Interval, "Only used by did:nuts/gRPC. Interval, formatted as Golang duration (e.g. 10m, 1h) at which BBolt database backups will be performed.")
	flagSet.String("storage.redis.address", defs.Redis.Address, "Only used by did:nuts/gRPC. Redis database server address. This can be a simple 'host:port' or a Redis connection URL with scheme, auth and other options.")
	flagSet.String("storage.redis.username", defs.Redis.Username, "Only used by did:nuts/gRPC. Redis database username. If set, it overrides the username in the connection URL.")
	flagSet.String("storage.redis.password", defs.Redis.Password, "Only used by did:nuts/gRPC. Redis database password. If set, it overrides the username in the connection URL.")
	flagSet.String("storage.redis.database", defs.Redis.Database, "Only used by did:nuts/gRPC. Redis database name, which is used as prefix every key. Can be used to have multiple instances use the same Redis instance.")
	flagSet.String("storage.redis.tls.truststorefile", defs.Redis.TLS.TrustStoreFile, "Only used by did:nuts/gRPC. PEM file containing the trusted CA certificate(s) for authenticating remote Redis servers. Can only be used when connecting over TLS (use 'rediss://' as scheme in address).")
	flagSet.String("storage.redis.sentinel.master", defs.Redis.Sentinel.Master, "Only used by did:nuts/gRPC. Name of the Redis Sentinel master. Setting this property enables Redis Sentinel.")
	flagSet.StringSlice("storage.redis.sentinel.nodes", defs.Redis.Sentinel.Nodes, "Only used by did:nuts/gRPC. Addresses of the Redis Sentinels to connect to initially. Setting this property enables Redis Sentinel.")
	flagSet.String("storage.redis.sentinel.username", defs.Redis.Sentinel.Username, "Only used by did:nuts/gRPC. Username for authenticating to Redis Sentinels.")
	flagSet.String("storage.redis.sentinel.password", defs.Redis.Sentinel.Password, "Only used by did:nuts/gRPC. Password for authenticating to Redis Sentinels.")
	flagSet.String("storage.sql.connection", defs.SQL.ConnectionString, "Connection string for the SQL database. "+
		"If not set it, defaults to a SQLite database stored inside the configured data directory. "+
		"Note: using SQLite is not recommended in production environments. "+
		"If using SQLite anyways, remember to enable foreign keys ('_foreign_keys=on') and the write-ahead-log ('_journal_mode=WAL').")

	// Hide flags for did:nuts/gRPC functionality
	flagSet.VisitAll(func(flag *pflag.Flag) {
		if strings.HasPrefix(flag.Name, "storage.redis") ||
			strings.HasPrefix(flag.Name, "storage.bbolt") {
			_ = flagSet.MarkHidden(flag.Name)
		}
	})

	return flagSet
}
