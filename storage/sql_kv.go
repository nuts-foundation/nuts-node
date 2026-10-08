/*
 * Copyright (C) 2026 Nuts community
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
	"database/sql"
	"errors"
	"fmt"
	"path"
	"time"

	"github.com/nuts-foundation/go-stoabs"
	stoabssql "github.com/nuts-foundation/go-stoabs/sql"
	"github.com/nuts-foundation/nuts-node/v6/core"
	"github.com/nuts-foundation/nuts-node/v6/storage/log"
	"github.com/nuts-foundation/nuts-node/v6/storage/sql_migrations"
)

// sqlKVLockTimeout is the time a writable KV transaction waits for the per-store write lock.
// Writers are serialized in-process (like bbolt); with SQL round trips a write transaction takes milliseconds,
// so this only trips when something is badly stuck.
const sqlKVLockTimeout = 5 * time.Second

// sqlKVDatabase serves the key-value stores from the node's SQL database, using the go-stoabs SQL backend.
// The shelf tables are created by sql_migrations.Migration012KVStores; the backend itself executes no DDL.
type sqlKVDatabase struct {
	db      *sql.DB
	dialect stoabssql.Dialect
}

// newSQLKVDatabase creates the SQL KV database adapter for the given database type, sharing the engine's
// connection pool. SQLite is not supported: it is a file on disk like bbolt and shares its single-instance and
// network-volume limitations, so there is nothing to gain over the bbolt backend.
func newSQLKVDatabase(dbType string, sharedDB *sql.DB) (*sqlKVDatabase, error) {
	switch dbType {
	case "postgres":
		return &sqlKVDatabase{db: sharedDB, dialect: stoabssql.Postgres()}, nil
	case "mysql":
		return &sqlKVDatabase{db: sharedDB, dialect: stoabssql.MySQL()}, nil
	case "sqlserver", "azuresql":
		return &sqlKVDatabase{db: sharedDB, dialect: stoabssql.SQLServer()}, nil
	case "sqlite":
		return nil, errors.New("storage.kv.backend=sql requires a database server (PostgreSQL, MySQL or SQL Server); SQLite is not supported, use the bbolt backend")
	default:
		return nil, fmt.Errorf("unsupported SQL database type for KV stores: %s", dbType)
	}
}

func (s *sqlKVDatabase) createStore(moduleName string, storeName string) (stoabs.KVStore, error) {
	log.Logger().
		WithField(core.LogFieldStore, path.Join(moduleName, storeName)).
		Debug("Creating SQL KV store")
	return stoabssql.Wrap(s.db, s.dialect, sql_migrations.KVTableName(moduleName, storeName),
		stoabs.WithLockAcquireTimeout(sqlKVLockTimeout))
}

func (s *sqlKVDatabase) getClass() Class {
	return PersistentStorageClass
}

func (s *sqlKVDatabase) close() {
	// the connection pool belongs to the engine
}
