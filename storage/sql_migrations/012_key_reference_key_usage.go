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

	"github.com/pressly/goose/v3"
)

// keyReferenceKeyUsage012 provides the per-database-type statements for adding
// key_reference.key_usage as NOT NULL with no default that lingers for future inserts, keyed by
// database type:
//
//   - Adding a NOT NULL column to a non-empty table needs a DEFAULT to backfill existing rows with
//     - there's no way around that in a single ADD COLUMN statement - so every dialect's addColumn
//     statement backfills existing rows to 31 ("everything": what every key was assumed to support
//     before this column existed) via `... NOT NULL DEFAULT 31`.
//   - Postgres and MySQL can then drop that default again immediately afterward with a plain
//     `ALTER COLUMN ... DROP DEFAULT`, so it doesn't linger for future inserts.
//   - SQL Server ties a default to a separate, named constraint object rather than to the column
//     itself, so dropping it means naming that constraint explicitly when adding the column, then
//     dropping the constraint by name.
//   - SQLite has no ALTER COLUMN or DROP CONSTRAINT syntax at all, so it's stuck with a permanent
//     default. That's harmless in practice: crypto.Crypto.New() always writes a real value
//     explicitly for every key it creates, so nothing ever relies on it.
var keyReferenceKeyUsage012 = map[string]struct{ addColumn, dropDefault string }{
	"sqlite": {
		addColumn: "alter table key_reference add column key_usage SMALLINT not null default 31",
	},
	"postgres": {
		addColumn:   "alter table key_reference add column key_usage SMALLINT not null default 31",
		dropDefault: "alter table key_reference alter column key_usage drop default",
	},
	"mysql": {
		addColumn:   "alter table key_reference add column key_usage SMALLINT not null default 31",
		dropDefault: "alter table key_reference alter column key_usage drop default",
	},
	"sqlserver": {
		addColumn:   "alter table key_reference add key_usage SMALLINT not null constraint df_key_reference_key_usage default 31",
		dropDefault: "alter table key_reference drop constraint df_key_reference_key_usage",
	},
	"azuresql": {
		addColumn:   "alter table key_reference add key_usage SMALLINT not null constraint df_key_reference_key_usage default 31",
		dropDefault: "alter table key_reference drop constraint df_key_reference_key_usage",
	},
}

// Migration012KeyReferenceKeyUsage returns the goose Go migration (version 12) that adds
// key_reference.key_usage: a bitmask of the DIDKeyFlags the key can actually be used for, using
// the same encoding as did_verification_method.key_types:
//
//	0x01 - AssertionMethod
//	0x02 - Authentication
//	0x04 - CapabilityDelegation
//	0x08 - CapabilityInvocation
//	0x10 - KeyAgreement
//
// This is a Go migration (rather than a .sql file) because, like Migration011CredentialPropValueType,
// the required syntax differs per database (see keyReferenceKeyUsage012). crypto.Crypto.Migrate()
// corrects the "everything" backfill assumption afterwards for backends, like Azure Key Vault, whose
// keys can't actually do everything.
func Migration012KeyReferenceKeyUsage(dbType string) *goose.Migration {
	statements, ok := keyReferenceKeyUsage012[dbType]
	return goose.NewGoMigration(12,
		&goose.GoFunc{RunTx: func(ctx context.Context, tx *sql.Tx) error {
			if !ok {
				return fmt.Errorf("unsupported database type: %s", dbType)
			}
			if _, err := tx.ExecContext(ctx, statements.addColumn); err != nil {
				return err
			}
			if statements.dropDefault != "" {
				if _, err := tx.ExecContext(ctx, statements.dropDefault); err != nil {
					return err
				}
			}
			return nil
		}},
		&goose.GoFunc{RunTx: func(ctx context.Context, tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, "alter table key_reference drop column key_usage")
			return err
		}},
	)
}
