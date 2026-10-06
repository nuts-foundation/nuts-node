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

package sql_migrations

import (
	"context"
	"database/sql"
	"fmt"

	stoabssql "github.com/nuts-foundation/go-stoabs/sql"
	"github.com/pressly/goose/v3"
)

// KVShelf identifies one shelf of one key-value store. Module and store names are as passed to
// storage.Provider.GetKVStore (module names lower-cased).
type KVShelf struct {
	Module string
	Store  string
	Shelf  string
}

// TableName returns the name of the SQL table that holds the shelf when the key-value stores are on SQL.
// It must produce the same name as the storage engine's SQL KV database adapter.
func (s KVShelf) TableName() string {
	return KVTableName(s.Module, s.Store)(s.Shelf)
}

// KVTableName returns the shelf-to-table-name mapping for the given store.
func KVTableName(module string, store string) stoabssql.TableNameFunc {
	return stoabssql.PrefixTableName("kv_" + module + "_" + store)
}

// KVShelves is the fixed inventory of key-value shelves used by the did:nuts stack.
// The SQL KV backend executes no DDL, so every shelf an engine uses must be listed here and created by
// Migration012KVStores. Adding a shelf in code requires a new migration that creates its table.
var KVShelves = []KVShelf{
	// network DAG (network/dag)
	{"network", "data", "metadata"},
	{"network", "data", "documents"},
	{"network", "data", "heads"},
	{"network", "data", "clocks"},
	{"network", "data", "payloads"},
	{"network", "data", "xorBucket"},
	{"network", "data", "ibltBucket"},
	// network notifier job shelves ("_<notifier name>_jobs", network/dag/notifier.go)
	{"network", "data", "_nats_jobs"},
	{"network", "data", "_private_jobs"},
	{"network", "data", "_vcr_vcs_jobs"},
	{"network", "data", "_vcr_revocations_jobs"},
	{"network", "data", "_vdr_jobs"},
	// peer connection backoffs (network/transport/grpc/backoff.go)
	{"network", "connections", "backoff"},
	// did:nuts DID store (vdr/didnuts/didstore)
	{"vdr", "didstore", "latestV2"},
	{"vdr", "didstore", "metadataV2"},
	{"vdr", "didstore", "txRefV2"},
	{"vdr", "didstore", "documentsV2"},
	{"vdr", "didstore", "eventsV2"},
	{"vdr", "didstore", "conflictedV2"},
	{"vdr", "didstore", "statsV2"},
	// go-leia backup shelves (vcr, vcr/issuer, vcr/verifier)
	{"vcr", "backup-credentials", "credentials"},
	{"vcr", "backup-issued-credentials", "credentials"},
	{"vcr", "backup-issued-credentials", "revocations"},
	{"vcr", "backup-revoked-credentials", "revocations"},
}

// kvColumnTypes012 holds the per-database column definitions for the shelf tables.
// Keys are at most ~60 bytes (did:nuts DID + version); everything else is a 32-byte hash, a 4-byte clock or a
// short fixed string. Values can be tens of KBs (credentials, IBLT pages), so the value type is unbounded.
var kvColumnTypes012 = map[string]struct{ key, value string }{
	"sqlite":    {key: `"key" BLOB NOT NULL PRIMARY KEY`, value: `"value" BLOB NOT NULL`},
	"postgres":  {key: `"key" BYTEA NOT NULL PRIMARY KEY`, value: `"value" BYTEA NOT NULL`},
	"mysql":     {key: "`key` VARBINARY(128) NOT NULL PRIMARY KEY", value: "`value` LONGBLOB NOT NULL"},
	"sqlserver": {key: `[key] VARBINARY(128) NOT NULL PRIMARY KEY`, value: `[value] VARBINARY(MAX) NOT NULL`},
	"azuresql":  {key: `[key] VARBINARY(128) NOT NULL PRIMARY KEY`, value: `[value] VARBINARY(MAX) NOT NULL`},
}

func kvQuoteTable(dbType string, name string) string {
	switch dbType {
	case "mysql":
		return "`" + name + "`"
	case "sqlserver", "azuresql":
		return "[" + name + "]"
	default:
		return `"` + name + `"`
	}
}

// Migration012KVStores returns the goose Go migration (version 12) that creates the tables for the key-value
// shelves in KVShelves. The tables are created on every database, whether the node uses the SQL KV backend or not,
// so that switching storage.kv.backend never requires out-of-order migrations.
//
// It is a Go migration because the binary column types and identifier quoting differ per database, and it runs
// via RunTx for the same reason as Migration011CredentialPropValueType (SQLite's single-connection pool).
func Migration012KVStores(dbType string) *goose.Migration {
	types, ok := kvColumnTypes012[dbType]
	return goose.NewGoMigration(12,
		&goose.GoFunc{RunTx: func(ctx context.Context, tx *sql.Tx) error {
			if !ok {
				return fmt.Errorf("unsupported database type for KV store tables: %s", dbType)
			}
			for _, shelf := range KVShelves {
				table := kvQuoteTable(dbType, shelf.TableName())
				var stmt string
				if dbType == "sqlserver" || dbType == "azuresql" {
					stmt = fmt.Sprintf("IF OBJECT_ID(N'%s', N'U') IS NULL CREATE TABLE %s (%s, %s)", shelf.TableName(), table, types.key, types.value)
				} else {
					stmt = fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (%s, %s)", table, types.key, types.value)
				}
				if _, err := tx.ExecContext(ctx, stmt); err != nil {
					return fmt.Errorf("create table %s: %w", shelf.TableName(), err)
				}
			}
			return nil
		}},
		&goose.GoFunc{RunTx: func(ctx context.Context, tx *sql.Tx) error {
			for _, shelf := range KVShelves {
				if _, err := tx.ExecContext(ctx, "DROP TABLE "+kvQuoteTable(dbType, shelf.TableName())); err != nil {
					return fmt.Errorf("drop table %s: %w", shelf.TableName(), err)
				}
			}
			return nil
		}},
	)
}
