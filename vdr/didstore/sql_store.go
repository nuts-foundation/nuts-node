package didstore

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"strings"
)

var _ Store = (*sqlStore)(nil)

type sqlStore struct {
	db *sql.DB
}

func NewSQLStore(db *sql.DB) (Store, error) {
	s := &sqlStore{
		db: db,
	}
	err := s.migrate()
	return s, err
}

func (s sqlStore) migrate() error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS did_documents (
			id VARCHAR(1000),
			tx_ref VARCHAR(255),
			hash VARCHAR(255),
			deactivated BOOLEAN,
       		is_latest_version BOOLEAN,
       		data JSON
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

func (s sqlStore) Add(didDocument did.Document, tx Transaction) error {
	data, _ := didDocument.MarshalJSON()
	_, err := s.db.Exec("INSERT INTO did_documents (id, tx_ref, hash, data, deactivated) VALUES (?, ?, ?, ?, ?)",
		didDocument.ID.String(), tx.Ref.String(), tx.PayloadHash.String(), data, isDeactivated(didDocument))
	if err != nil {
		return fmt.Errorf("failed to insert DID document (id=%s): %w", didDocument.ID, err)
	}
	return nil
}

func (s sqlStore) Conflicted(fn types.DocIterator) error {
	//TODO implement me
	panic("implement me")
}

func (s sqlStore) ConflictedCount() (uint, error) {
	//TODO implement me
	panic("implement me")
}

func (s sqlStore) DocumentCount() (uint, error) {
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM did_documents").Scan(&count)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	return uint(count), nil
}

func (s sqlStore) Iterate(fn types.DocIterator) error {
	rows, err := s.db.Query("SELECT id, data FROM did_documents")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var data []byte
		if err := rows.Scan(&id, &data); err != nil {
			return err
		}
		var document did.Document
		if err := json.Unmarshal(data, &document); err != nil {
			return fmt.Errorf("failed to unmarshal DID document (id=%s): %w", id, err)
		}
		if err := fn(document, types.DocumentMetadata{}); err != nil {
			return err
		}
	}
}

func (s sqlStore) Resolve(id did.DID, metadata *types.ResolveMetadata) (*did.Document, *types.DocumentMetadata, error) {
	columnsSlice := []string{"tx_ref", "data", "deactivated"}
	columns := strings.Join(columnsSlice, ", ")
	allowDeactivated := metadata != nil && metadata.AllowDeactivated

	if metadata == nil {
		rows, err := s.db.Query("SELECT "+columns+" FROM did_documents WHERE id = ? AND is_latest_version = 1", id.String())
		if err != nil {
			return nil, nil, fmt.Errorf("failed to query DID document (id=%s): %w", id, err)
		}
		defer rows.Close()
		var versions []did.Document
		for rows.Next() {
			var txRef string
			var data []byte
			var deactivated bool
			if err := rows.Scan(&txRef, &data, &deactivated); err != nil {
				return nil, nil, fmt.Errorf("failed to scan DID document (id=%s): %w", id, err)
			}
			var document did.Document
			if err := json.Unmarshal(data, &document); err != nil {
				return nil, nil, fmt.Errorf("failed to unmarshal DID document (id=%s, tx=%s): %w", id, txRef, err)
			}
			if deactivated && !allowDeactivated {
				// TODO: is this right?
				return nil, nil, types.ErrDeactivated
			}
			versions = append(versions, document)
		}
		switch len(versions) {
		case 0:
			return nil, nil, types.ErrNotFound
		case 1:
			return &versions[0], nil, nil
		default:
			// conflicted
			var mergedDocument = versions[0]
			for i, version := range versions {
				if i == 0 {
					continue
				}
				mergedDocument = mergeDocuments(mergedDocument, version)
			}
			return &mergedDocument, nil, nil
		}
	} else {
		if metadata.Hash != nil {
			err := s.db.QueryRow("SELECT "+columns+" FROM did_documents WHERE id = ? AND hash = ?", id.String(), metadata.Hash.String()).Scan(&data)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to query DID document (id=%s): %w", id, err)
			}
		}
	}
	//

	metadata.ResolveTime
}
