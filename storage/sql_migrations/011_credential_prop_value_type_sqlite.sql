-- +goose Up
-- SQLite has no ALTER COLUMN/MODIFY COLUMN syntax to change a column's type, and doesn't enforce
-- varchar length limits in the first place, so there's nothing to do here. This file replaces
-- 011_credential_prop_value_type.sql for SQLite (see engine.go), keeping the migration version
-- in sync across database types.

-- +goose Down
