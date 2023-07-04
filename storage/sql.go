package storage

import (
	"database/sql"
	"fmt"
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/nuts-node/storage/log"
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
	panic("Key-value storage is not supported for SQL databases")
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

func DoSqlTx(db *sql.DB, receiver func(tx *sql.Tx) error) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	rollback := true
	defer func() {
		if rollback {
			log.Logger().WithError(err).Warn("Rolling back SQL transaction due to application error")
			if err = tx.Rollback(); err != nil {
				log.Logger().WithError(err).Warn("SQL transaction rollback failed")
			}
		}
	}()
	err = receiver(tx)
	if err == nil {
		rollback = false
		if err = tx.Commit(); err != nil {
			return fmt.Errorf("failed to commit SQL transaction: %w", err)
		}
	}
	return err
}
