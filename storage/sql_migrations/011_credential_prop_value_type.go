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

	"github.com/pressly/goose/v3"
)

// credentialPropValueType011 is the (up, down) ALTER TABLE statement that changes the type of
// credential_prop.value, keyed by database type. The syntax for changing an existing column's
// type is not portable, e.g.:
//
//	postgres:           alter table credential_prop alter column value type TEXT;
//	mysql:              alter table credential_prop modify column value TEXT;
//	sqlserver/azuresql: alter table credential_prop alter column value VARCHAR(MAX);
//
// SQLite has no ALTER COLUMN/MODIFY COLUMN syntax at all, and doesn't enforce varchar length
// limits in the first place, so there's nothing to do there; it's simply absent from this map.
//
// See https://github.com/nuts-foundation/nuts-node/issues/4392.
var credentialPropValueType011 = map[string]struct{ up, down string }{
	"postgres": {
		up:   "alter table credential_prop alter column value type TEXT",
		down: "alter table credential_prop alter column value type varchar(500)",
	},
	"mysql": {
		up:   "alter table credential_prop modify column value TEXT",
		down: "alter table credential_prop modify column value varchar(500)",
	},
	"sqlserver": {
		up:   "alter table credential_prop alter column value VARCHAR(MAX)",
		down: "alter table credential_prop alter column value varchar(500)",
	},
	"azuresql": {
		up:   "alter table credential_prop alter column value VARCHAR(MAX)",
		down: "alter table credential_prop alter column value varchar(500)",
	},
}

// Migration011CredentialPropValueType returns the goose Go migration (version 11) that widens
// credential_prop.value from varchar(500) to an unbounded text type, per database type
// (see credentialPropValueType011).
//
// This is a Go migration (rather than a .sql file) because the required syntax differs per
// database, and it runs via RunTx (rather than RunDB): the latter needs to acquire a second
// connection from the pool to run the migration, which deadlocks against SQLite's
// single-connection pool (see storage.initSQLDatabase).
func Migration011CredentialPropValueType(dbType string) *goose.Migration {
	statements, ok := credentialPropValueType011[dbType]
	return goose.NewGoMigration(11,
		&goose.GoFunc{RunTx: func(ctx context.Context, tx *sql.Tx) error {
			if !ok {
				return nil
			}
			_, err := tx.ExecContext(ctx, statements.up)
			return err
		}},
		&goose.GoFunc{RunTx: func(ctx context.Context, tx *sql.Tx) error {
			if !ok {
				return nil
			}
			_, err := tx.ExecContext(ctx, statements.down)
			return err
		}},
	)
}
