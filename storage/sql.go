package storage

import (
	"database/sql"
	"fmt"
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/go-stoabs/postgres"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/storage/log"
	"path"
)

// SQLConfig specifies config for SQL databases (currently only Postgres).
type SQLConfig struct {
	ConnectionString string `koanf:"connection"`
}

func (c SQLConfig) isConfigured() bool {
	return c.ConnectionString != ""
}

func createSQLDatabase(config SQLConfig) (*sqlDatabase, error) {
	db, err := sql.Open("postgres", config.ConnectionString)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to postgres: %w", err)
	}
	return &sqlDatabase{
		config: config,
		db:     db,
	}, nil
}

type sqlDatabase struct {
	config SQLConfig
	db     *sql.DB
}

func (b *sqlDatabase) createStore(moduleName string, storeName string) (stoabs.KVStore, error) {
	log.Logger().
		WithField(core.LogFieldStore, path.Join(moduleName, storeName)).
		Debug("Creating SQL store")
	return postgres.CreatePostgresStore(b.db)
}

func (b sqlDatabase) getClass() Class {
	return PersistentStorageClass
}

func (b sqlDatabase) close() {
	err := b.db.Close()
	if err != nil {
		log.Logger().WithError(err).Error("Failed to close SQL database")
	}
}
