package storage

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	_ "github.com/lib/pq"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
)

func NewSQLRevocationStore(db *sql.DB, role Role) (*SQLRevocationStore, error) {
	if role != RoleIssuer && role != RoleHolderVerifier {
		return nil, errors.New("invalid role")
	}
	store := &SQLRevocationStore{
		db:   db,
		role: role,
	}
	err := store.migrate()
	return store, err
}

// SQLRevocationStore stores revocations in a SQL database.
type SQLRevocationStore struct {
	db   *sql.DB
	role Role
}

func (s SQLRevocationStore) migrate() error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS revocations (
			subject VARCHAR(1000) NOT NULL,
			data jsonb NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS revocations_subject ON revocations (subject)`,
		`CREATE TABLE IF NOT EXISTS issued_revocations (
			subject VARCHAR(255) PRIMARY KEY
		)`,
		`CREATE TABLE IF NOT EXISTS received_revocations (
			subject VARCHAR(255) PRIMARY KEY 
		)`,
	}

	for _, statement := range statements {
		_, err := s.db.Exec(statement)
		if err != nil {
			return fmt.Errorf("failed to execute migration statement %s: %w", statement, err)
		}
	}
	return nil
}

func (s SQLRevocationStore) GetRevocations(credentialID ssi.URI) ([]*credential.Revocation, error) {
	rows, err := s.db.Query(fmt.Sprintf("SELECT r.data "+
		"FROM %s t "+
		"INNER JOIN revocations r ON t.subject = r.subject "+
		"WHERE t.subject = $1", s.tableName()), credentialID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to get revocations (subject=%s): %w", credentialID, err)
	}
	return s.readResults(rows)
}

func (s SQLRevocationStore) StoreRevocation(revocation credential.Revocation) error {
	data, _ := json.Marshal(revocation)

	return doTX(s.db, func(tx *sql.Tx) error {
		// There can be multiple revocations for the same subject,
		// so check for subject (has an index, so speeds up) and revocation data
		if exists, err := queryExists(tx, "SELECT COUNT(subject) FROM revocations WHERE subject = $1 AND data = $2", revocation.Subject.String(), data); err != nil {
			return fmt.Errorf("failed to check if revocation exists (id=%s): %w", revocation.Subject, err)
		} else if exists {
			// already exists
			return nil
		}
		_, err := s.db.Exec("INSERT INTO revocations (subject, data) VALUES ($1, $2)", revocation.Subject.String(), data)
		if err != nil {
			return fmt.Errorf("failed to store revocation (subject=%s): %w", revocation.Subject, err)
		}

		// Check if the revocation is stored for this role
		query := fmt.Sprintf("SELECT COUNT(subject) FROM %s WHERE subject = $1", s.tableName())
		if exists, err := queryExists(tx, query, revocation.Subject.String()); err != nil {
			return fmt.Errorf("failed to check if revocation (%s) exists (id=%s): %w", s.tableName(), revocation.Subject, err)
		} else if exists {
			// already exists
			return nil
		}
		query = fmt.Sprintf("INSERT INTO %s (subject) VALUES ($1)", s.tableName())
		_, err = s.db.Exec(query, revocation.Subject.String())
		if err != nil {
			return fmt.Errorf("failed to store revocation (subject=%s): %w", revocation.Subject, err)
		}
		return nil
	})

	return nil
}

func (s SQLRevocationStore) Count() (int, error) {
	var count int
	err := s.db.QueryRow(fmt.Sprintf("SELECT COUNT(t.subject) "+
		"FROM %s t "+
		"INNER JOIN revocations r ON t.subject = r.subject", s.tableName())).Scan(&count)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	return count, nil
}

func (s SQLRevocationStore) readResults(rows *sql.Rows) ([]*credential.Revocation, error) {
	var results []*credential.Revocation
	for rows.Next() {
		var data []byte
		err := rows.Scan(&data)
		if err != nil {
			return nil, fmt.Errorf("failed to get results: %w", err)
		}

		var result credential.Revocation
		err = json.Unmarshal(data, &result)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal credential: %w", err)
		}
		results = append(results, &result)
	}
	return results, nil
}

func (s SQLRevocationStore) tableName() string {
	var tableName string
	if s.role == RoleIssuer {
		tableName = "issued_revocations"
	} else {
		tableName = "received_revocations"
	}
	return tableName
}
