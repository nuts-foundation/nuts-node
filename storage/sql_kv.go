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

// sqlKVMaxOpenConns is the pool size of the dedicated SQLite handle for the KV stores, see newSQLKVDatabase.
const sqlKVMaxOpenConns = 10

// sqlKVDatabase serves the key-value stores from the node's SQL database, using the go-stoabs SQL backend.
// The shelf tables are created by sql_migrations.Migration012KVStores; the backend itself executes no DDL.
type sqlKVDatabase struct {
	db      *sql.DB
	dialect stoabssql.Dialect
	// ownsDB is true when db was opened by this adapter (SQLite) and must be closed on shutdown.
	ownsDB bool
}

// newSQLKVDatabase creates the SQL KV database adapter for the given database type.
//
// For every database except SQLite it shares the engine's connection pool. SQLite is special: the engine's pool is
// limited to a single connection (see initSQLDatabase), and the did:nuts stack nests read transactions
// (e.g. the DAG verifies a transaction's signature by resolving the signing key from the DID store while its own read
// transaction is open). With one connection that nesting deadlocks, so SQLite gets a dedicated handle with a small
// pool and WAL mode, which allows concurrent readers alongside the single writer.
func newSQLKVDatabase(dbType string, sharedDB *sql.DB, sqliteDSN string) (*sqlKVDatabase, error) {
	switch dbType {
	case "sqlite":
		db, err := sql.Open("sqlite", sqliteDSN+"&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
		if err != nil {
			return nil, err
		}
		db.SetMaxOpenConns(sqlKVMaxOpenConns)
		return &sqlKVDatabase{db: db, dialect: stoabssql.SQLite(), ownsDB: true}, nil
	case "postgres":
		return &sqlKVDatabase{db: sharedDB, dialect: stoabssql.Postgres()}, nil
	case "mysql":
		return &sqlKVDatabase{db: sharedDB, dialect: stoabssql.MySQL()}, nil
	case "sqlserver", "azuresql":
		return &sqlKVDatabase{db: sharedDB, dialect: stoabssql.SQLServer()}, nil
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
	if s.ownsDB {
		if err := s.db.Close(); err != nil {
			log.Logger().WithError(err).Error("Unable to close SQL KV database handle")
		}
	}
}
