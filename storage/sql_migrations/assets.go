package sql_migrations

import "embed"

//go:embed *.sql
var SQLMigrationsFS embed.FS
