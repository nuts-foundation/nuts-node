package storage

import (
	"database/sql"
	"errors"
)

func queryExists(tx *sql.Tx, query string, args ...interface{}) (bool, error) {
	var count int
	err := tx.QueryRow(query, args...).Scan(&count)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	return count != 0, nil
}
