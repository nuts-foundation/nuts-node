package didstore

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lib/pq"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/vcr/log"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/prometheus/client_golang/prometheus"
	"sort"
	"time"
)

var _ Store = (*sqlStore)(nil)

type sqlStore struct {
	db                      *sql.DB
	operationDurationMetric *prometheus.HistogramVec
}

func NewSQLStore(db *sql.DB) (Store, error) {
	s := &sqlStore{
		db: db,
	}
	s.operationDurationMetric = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "nuts",
		Subsystem: "vdr",
		Name:      "sql_did_store_operation_duration_ms",
		Help:      "Duration of operations on the VDR's SQL DID store in milliseconds",
		Buckets:   []float64{5, 10, 20, 50, 100, 500, 1000, 2000, 5000},
	}, []string{"op"})
	err := prometheus.Register(s.operationDurationMetric)
	if err != nil && err.Error() != (prometheus.AlreadyRegisteredError{}).Error() { // No unwrap on prometheus.AlreadyRegisteredError
		return nil, err
	}
	err = s.migrate()
	return s, err
}

func (s sqlStore) migrate() error {
	log.Logger().Debug("Migrating SQL DID store")
	statements := []string{
		`CREATE TABLE IF NOT EXISTS did_documents (
			did VARCHAR(1000) NOT NULL,
			tx_ref VARCHAR(255) NOT NULL PRIMARY KEY,
			clock INTEGER NOT NULL,
			hash VARCHAR(255) NOT NULL,
			deactivated BOOLEAN NOT NULL,
       		timestamp TIMESTAMP NOT NULL,
       		version INTEGER NOT NULL,
       		data JSON NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS did_prevs (
		    did VARCHAR(1000) NOT NULL,
			tx_ref VARCHAR(255) NOT NULL,
			prev_hash VARCHAR(255) NOT NULL
		)`,
		`CREATE OR REPLACE VIEW did_documents_current_versions AS
			SELECT did, tx_ref, data
			FROM did_documents docs
			WHERE NOT EXISTS(
				SELECT 1
				FROM did_prevs
				WHERE did=docs.did AND docs.tx_ref=prev_hash)
			ORDER BY did, version ASC`,
		`CREATE INDEX IF NOT EXISTS did_documents_tx ON did_documents (tx_ref)`,
		`CREATE INDEX IF NOT EXISTS did_documents_hash ON did_documents (hash)`,
		`CREATE INDEX IF NOT EXISTS did_documents_did ON did_documents (did)`,
		`CREATE INDEX IF NOT EXISTS did_documents_tx_did ON did_documents (tx_ref, did)`,
		`CREATE INDEX IF NOT EXISTS did_prevs_tx ON did_prevs (tx_ref)`,
		`CREATE INDEX IF NOT EXISTS did_prevs_did ON did_prevs (did)`,
		`ALTER TABLE did_prevs ADD CONSTRAINT fk_did_prev_tx FOREIGN KEY(tx_ref) REFERENCES did_documents(tx_ref)`,
		`ALTER TABLE did_prevs ADD CONSTRAINT uq_did_prevs UNIQUE (tx_ref, prev_hash)`,
	}

	for _, statement := range statements {
		_, err := s.db.Exec(statement)
		// Ignore errors for duplicate constraints
		var pqErr *pq.Error
		if errors.As(err, &pqErr) {
			switch pqErr.Code.Name() {
			case "duplicate_object":
				fallthrough
			case "duplicate_table":
				// this is OK
				continue
			default:
				// this is not OK
			}
		}
		if err != nil {
			return fmt.Errorf("failed to execute migration statement %s: %w", statement, err)
		}
	}
	return nil
}

func (s sqlStore) Add(didDocument did.Document, tx Transaction) error {
	// startTime is used to measure the duration of the operation.
	// Operation duration for already existing documents is not measured, since it's so fast it would skew the metrics.
	var startTime time.Time
	err := storage.DoSqlTx(s.db, func(sqlTx *sql.Tx) error {
		// Already exists? Ignore.
		var txRef string
		err := sqlTx.QueryRow("SELECT 1 FROM did_documents WHERE tx_ref=$1", tx.Ref.String()).Scan(&txRef)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("failed to check if transaction already exists: %w", err)
		} else if err == nil {
			// Already exists
			return nil
		}

		startTime = time.Now()
		// Get version of last version, to determine the new version
		var version int
		err = sqlTx.QueryRow("SELECT last.version "+
			"FROM did_documents doc INNER JOIN ( "+
			" SELECT MAX(version) AS version "+
			" FROM did_documents "+
			" WHERE did=$1 "+
			") AS last ON doc.version = last.version "+
			"WHERE doc.did=$1",
			didDocument.ID.String()).Scan(&version)
		if err != nil && err != sql.ErrNoRows {
			return fmt.Errorf("failed to get max version of DID document (did=%s): %w", didDocument.ID, err)
		}
		version++

		// Then, insert
		data, _ := didDocument.MarshalJSON()
		_, err = sqlTx.Exec("INSERT INTO did_documents "+
			"(did, tx_ref, hash, data, deactivated, timestamp, version, clock) "+
			"VALUES "+
			"($1, $2, $3, $4, $5, $6, $7, $8)",
			didDocument.ID.String(), tx.Ref.String(), tx.PayloadHash.String(), data, isDeactivated(didDocument),
			tx.SigningTime, version, tx.Clock)
		// Duplicates should be ignored
		if err != nil {
			return fmt.Errorf("failed to insert DID document (did=%s): %w", didDocument.ID, err)
		}

		// Insert previous TXs (but only if the TXs is about the same DID)
		for _, prev := range tx.Previous {
			_, err = sqlTx.Exec("INSERT INTO did_prevs (did, tx_ref, prev_hash) VALUES ($1, $2, $3)", didDocument.ID.String(), tx.Ref.String(), prev.String())
			if err != nil {
				return fmt.Errorf("failed to insert previous transaction (txRef=%s, prev=%s): %w", tx.Ref, prev, err)
			}
		}

		// Now sort all versions of this DID document
		if err = s.sortVersions(sqlTx, didDocument); err != nil {
			return err
		}

		return nil
	})
	if err == nil && !startTime.IsZero() {
		s.operationDurationMetric.WithLabelValues("Add").Observe(float64(time.Since(startTime).Milliseconds()))
	}
	return err
}

func (s sqlStore) Conflicted(fn types.DocIterator) error {
	// This could be optimized in 1 query, but there's not expected to be many conflicts, so an N+1 operation is acceptable for now.
	rows, err := s.db.Query(`SELECT did FROM did_documents_current_versions GROUP BY did HAVING COUNT(did) > 1`)
	if err != nil {
		return fmt.Errorf("conflicted DIDs query failure: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var currentDIDStr string
		if err := rows.Scan(&currentDIDStr); err != nil {
			return fmt.Errorf("failed to scan conflicted DIDs: %w", err)
		}
		currentDID, err := did.ParseDID(currentDIDStr)
		if err != nil {
			log.Logger().Warnf("failed to parse conflicted DID (did=%s): %s", currentDIDStr, err)
			continue
		}
		document, metadata, err := s.Resolve(*currentDID, nil)
		if err != nil {
			return fmt.Errorf("failed to resolve conflicted DID (did=%s): %w", currentDID, err)
		}
		if err := fn(*document, *metadata); err != nil {
			return fmt.Errorf("conflicted DID iterator failed (did=%s): %w", currentDID, err)
		}
	}
	return nil
}

func (s sqlStore) ConflictedCount() (uint, error) {
	var count uint
	err := s.db.QueryRow(`SELECT COUNT(*) 
		FROM (
			SELECT COUNT(did)
			FROM did_documents_current_versions 
			GROUP BY did 
			HAVING COUNT(did) > 1
		) AS c`).Scan(&count)
	if errors.Is(err, sql.ErrNoRows) {
		// No conflicts
		err = nil
	}
	return count, err
}

func (s sqlStore) DocumentCount() (uint, error) {
	var count int
	err := s.db.QueryRow("SELECT COUNT(DISTINCT did) FROM did_documents").Scan(&count)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	return uint(count), nil
}

func (s sqlStore) Iterate(fn types.DocIterator) error {
	rows, err := s.db.Query(`
		SELECT did, tx_ref, data, array(
        	select prev_hash 
        	from did_prevs p
        	where p.tx_ref = d.tx_ref
		) as prevs
		FROM did_documents_current_versions d`)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	} else if err != nil {
		return fmt.Errorf("query failure: %w", err)
	}
	defer rows.Close()

	// Each DID can return as multiple records in case they are conflicted.
	// Rows are returned in order of DID, so we collect transactions until a different DID is so returned.
	// Then we collect the versions and call the visitor.
	var txRef string
	var data []byte
	var versions []Transaction
	var currentDID string
	var previousDID string
	var prevs []string
	for rows.Next() {
		err := rows.Scan(&currentDID, &txRef, &data, (*pq.StringArray)(&prevs))
		if err != nil {
			return fmt.Errorf("scan failure: %w", err)
		}
		if previousDID == "" {
			// First iteration
			previousDID = currentDID
		}

		// If we have a new DID, collect versions and call the visitor
		if currentDID != previousDID && previousDID != "" {
			doc, md := s.versionsToDocument(versions, data)
			err = fn(*doc, *md)
			if err != nil {
				return fmt.Errorf("visitor failure: %w", err)
			}
			versions = nil
		}

		tx, err := s.unmarshalTX(data, txRef, prevs)
		if err != nil {
			return err
		}
		versions = append(versions, tx)
	}

	// For the last DID, there's no subsequent DID so we need to call the visitor here as well
	if len(versions) > 0 {
		doc, md := s.versionsToDocument(versions, data)
		err = fn(*doc, *md)
		if err != nil {
			return fmt.Errorf("visitor failure: %w", err)
		}
	}
	return nil
}

func (s sqlStore) Resolve(id did.DID, resolveMD *types.ResolveMetadata) (*did.Document, *types.DocumentMetadata, error) {
	var startTime = time.Now()
	var query string
	var queryArgs []interface{}
	var queryName string
	const columns = `tx_ref, data, array(
		select prev_hash
		from did_prevs p
		where p.tx_ref = d.tx_ref
	) as prevs`

	if resolveMD != nil {
		if resolveMD.Hash != nil {
			queryName = "hash"
			query = "SELECT " + columns + " FROM did_documents d WHERE hash=$1"
			queryArgs = []interface{}{resolveMD.Hash.String()}
		}
		if resolveMD.SourceTransaction != nil {
			queryName = "sourceTX"
			query = "SELECT " + columns + " FROM did_documents d WHERE tx_ref=$1 AND did=$2"
			queryArgs = []interface{}{resolveMD.SourceTransaction.String(), id.String()}
		}
	}
	if query == "" {
		queryName = "latest"
		query = "SELECT " + columns + " FROM did_documents_current_versions d WHERE did=$1"
		queryArgs = []interface{}{id.String()}
	}
	document, md, err := s.queryDocument(query, queryArgs...)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve DID version failed (%s, did=%s): %w", id, queryName, err)
	}

	s.operationDurationMetric.WithLabelValues("Resolve").Observe(float64(time.Since(startTime).Milliseconds()))

	// Was the document found?
	if document == nil {
		return nil, nil, types.ErrNotFound
	}
	// Do we allow deactivated documents?
	if isDeactivated(*document) && (resolveMD == nil || !resolveMD.AllowDeactivated) {
		return nil, nil, types.ErrDeactivated
	}
	return document, md, nil
}

func (s sqlStore) queryDocument(query string, args ...interface{}) (*did.Document, *types.DocumentMetadata, error) {
	rows, err := s.db.Query(query, args...)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, nil
	} else if err != nil {
		return nil, nil, fmt.Errorf("query failure: %w", err)
	}
	defer rows.Close()

	var txRef string
	var data []byte
	var versions []Transaction
	var prevs []string
	for rows.Next() {
		err := rows.Scan(&txRef, &data, (*pq.StringArray)(&prevs))
		if err != nil {
			return nil, nil, fmt.Errorf("scan failure: %w", err)
		}
		tx, err := s.unmarshalTX(data, txRef, prevs)
		if err != nil {
			return nil, nil, err
		}
		versions = append(versions, tx)
	}
	doc, md := s.versionsToDocument(versions, data)
	return doc, md, nil
}

func (s sqlStore) unmarshalTX(data []byte, txRef string, prevs []string) (Transaction, error) {
	var document did.Document
	if err := json.Unmarshal(data, &document); err != nil {
		return Transaction{}, fmt.Errorf("unmarshal failure (tx=%s): %w", txRef, err)
	}
	parsedRef, err := hash.ParseHex(txRef)
	if err != nil {
		return Transaction{}, err
	}

	var parsedPrevs []hash.SHA256Hash
	for _, prev := range prevs {
		parsedPrev, err := hash.ParseHex(prev)
		if err != nil {
			return Transaction{}, err
		}
		parsedPrevs = append(parsedPrevs, parsedPrev)
	}
	return Transaction{
		Ref:      parsedRef,
		document: &document,
		Previous: parsedPrevs,
	}, nil
}

func (s sqlStore) versionsToDocument(versions []Transaction, data []byte) (*did.Document, *types.DocumentMetadata) {
	switch len(versions) {
	case 0:
		return nil, nil
	case 1:
		md := types.DocumentMetadata{
			Hash:               hash.SHA256Sum(data), // TODO: should we use the stored hash instead?
			SourceTransactions: []hash.SHA256Hash{versions[0].Ref},
		}
		if len(versions[0].Previous) > 0 {
			// TODO: this should be the hash of the DID document, not of the TX ref
			md.PreviousHash = &versions[0].Previous[0]
		}
		return versions[0].document, &md
	default:
		// conflicted
		var mergedDocument = *versions[0].document
		var sourceTXs []hash.SHA256Hash
		for i, version := range versions {
			sourceTXs = append(sourceTXs, version.Ref)
			if i == 0 {
				continue
			}
			mergedDocument = mergeDocuments(mergedDocument, *version.document)
		}
		mergedDocumentBytes, _ := json.Marshal(mergedDocument)
		md := types.DocumentMetadata{
			// TODO: What about PreviousHash?
			SourceTransactions: sourceTXs,
			Hash:               hash.SHA256Sum(mergedDocumentBytes),
		}
		return &mergedDocument, &md
	}
}

func (s sqlStore) sortVersions(sqlTx *sql.Tx, didDocument did.Document) error {
	type record struct {
		txRef     string
		clock     uint32
		timestamp time.Time
		version   int
		hash      sql.NullString
	}

	rows, err := sqlTx.Query("SELECT tx_ref, clock, timestamp, version, hash FROM did_documents WHERE did = $1 ORDER BY version ASC", didDocument.ID.String())
	if err != nil {
		return fmt.Errorf("failed to query DID document versions (did=%s): %w", didDocument.ID, err)
	}
	defer rows.Close()
	var unsortedRecords []*record
	for rows.Next() {
		var curr record
		if err := rows.Scan(&curr.txRef, &curr.clock, &curr.timestamp, &curr.version, &curr.hash); err != nil {
			return fmt.Errorf("failed to scan DID document versions (did=%s): %w", didDocument.ID, err)
		}
		unsortedRecords = append(unsortedRecords, &curr)
	}
	var sortedRecords = append([]*record{}, unsortedRecords...)
	// TODO: Generated by Copilot, is this right?
	sort.SliceStable(sortedRecords, func(i, j int) bool {
		if sortedRecords[i].clock == sortedRecords[j].clock {
			return sortedRecords[i].timestamp.Before(sortedRecords[j].timestamp)
		}
		return sortedRecords[i].clock < sortedRecords[j].clock
	})

	// Document is conflicted if there's more than one record that is not referred to by another record
	// If that's the case, mark all of these records as conflicted.

	// Check unsorted vs sorted lists, only update changed records
	updateIdx := -1
	for i, unsortedRecord := range unsortedRecords {
		if *unsortedRecord != *sortedRecords[i] {
			// Versions need to be updated starting this record
			updateIdx = i
			break
		}
	}
	if updateIdx == -1 {
		// No changes in order; nothing to do
		return nil
	}

	// Update versions starting at updateIdx
	for i := updateIdx; i < len(sortedRecords); i++ {
		_, err := sqlTx.Exec("UPDATE did_documents SET version=$1 WHERE tx_ref=$2",
			i+1, sortedRecords[i].txRef)
		if err != nil {
			return fmt.Errorf("failed to update DID document version (did=%s): %w", didDocument.ID, err)
		}
	}

	return nil
}
