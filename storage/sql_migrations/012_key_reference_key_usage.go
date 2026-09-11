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
// This is a Go migration (rather than a .sql file) so the column can end up NOT NULL with no
// DEFAULT. A DEFAULT would let the database silently manufacture a value application code never
// actually chose - crypto.Crypto.New() always sets this value explicitly for every key it creates,
// so the only place that ever needs to fill in a value on its own is this one-time migration,
// backfilling rows that predate this column to 31 ("everything": what every key was assumed to
// support before this column existed). crypto.Crypto.Migrate() corrects that assumption afterwards
// for backends, like Azure Key Vault, whose keys can't actually do everything.
//
// SQLite has no ALTER COLUMN syntax, so it can't add the NOT NULL constraint to the existing column
// without rebuilding the whole table; the column stays nullable there, same carve-out as
// Migration011CredentialPropValueType. Application code still always writes a real value.
func Migration012KeyReferenceKeyUsage(dbType string) *goose.Migration {
	return goose.NewGoMigration(12,
		&goose.GoFunc{RunTx: func(ctx context.Context, tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, "alter table key_reference add column key_usage SMALLINT"); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, "update key_reference set key_usage = 31"); err != nil {
				return err
			}
			if dbType == "postgres" {
				if _, err := tx.ExecContext(ctx, "alter table key_reference alter column key_usage set not null"); err != nil {
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
