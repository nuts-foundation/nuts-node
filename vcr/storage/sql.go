package storage

import (
	"database/sql"
	"errors"
	"fmt"
	"github.com/nuts-foundation/nuts-node/vcr/log"
)

func doTX(db *sql.DB, receiver func(tx *sql.Tx) error) error {
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

func queryExists(tx *sql.Tx, query string, args ...interface{}) (bool, error) {
	var count int
	err := tx.QueryRow(query, args...).Scan(&count)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	return count != 0, nil
}
