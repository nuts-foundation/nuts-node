This directory contains SQL schema migrations, run at startup of the node.

Refer to https://pressly.github.io/goose/ on how to write migrations.

Files should be named according to the following: `<number>_<table/feature name>.sql`.
For instance: `002_usecase_list.sql`. Each file should contain `-- +goose Up` and `-- +goose Down`

If a migration needs to change an existing column's type, the required syntax differs per database
(`ALTER COLUMN ... TYPE` vs `MODIFY COLUMN`, etc.) and SQLite doesn't support it at all. For that
case, use a Go migration (`goose.NewGoMigration`, registered via `goose.WithGoMigrations` in
`engine.go`) instead of a `.sql` file, so the per-database statement can be picked with a plain Go
switch/map on the database type. See `alterCredentialPropValueType` in `engine.go` for an example.

AVOID changing migrations in master (unless the migration breaks the node horribly) for those running a `master` version.
DO NOT alter migrations in a released version: it might break vendor deployments or cause data corruption.

DID and ID column length are set at 370 and 415 characters:
- domain names have a max length of 253
- `did:web:` has length 8
- for an additional path for did:web we could define max label length=63 + 1 (:)
- for the identifier a base64 encoded sha256 (44 chars) or uuid v4 (36 chars) would suffice (+1 for :)

- in bytes this is 1480 and 1660 bytes for a 4byte utf8 representation.