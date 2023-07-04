package storage

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lib/pq"
	_ "github.com/lib/pq"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/vcr/log"
	"github.com/nuts-foundation/nuts-node/vcr/types"
	"github.com/piprate/json-gold/ld"
	"strconv"
	"strings"
)

type Role string

const (
	RoleIssuer         Role = "issuer"
	RoleHolderVerifier      = "holder_verifier"
)

func NewSQLCredentialStore(db *sql.DB, role Role, documentLoader ld.DocumentLoader) (*SQLCredentialStore, error) {
	if role != RoleIssuer && role != RoleHolderVerifier {
		return nil, errors.New("invalid role")
	}
	store := &SQLCredentialStore{
		db:             db,
		documentLoader: documentLoader,
		role:           role,
	}
	err := store.migrate()
	return store, err
}

// SQLCredentialStore stores credentials and revocations in a SQL database.
// The schema is as follows:
type SQLCredentialStore struct {
	db             *sql.DB
	documentLoader ld.DocumentLoader
	role           Role
}

func (s SQLCredentialStore) migrate() error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS verifiable_credentials (
			id VARCHAR(1000) PRIMARY KEY,
			issuer VARCHAR(1000) NOT NULL,
			type text[] NOT NULL,
			subject_json jsonb NOT NULL,
			data json NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS subject_json_gin ON verifiable_credentials USING GIN (subject_json)`,
		`CREATE INDEX IF NOT EXISTS credential_type ON verifiable_credentials USING GIN (type)`,
		`CREATE TABLE IF NOT EXISTS issued_verifiable_credentials (
			id VARCHAR(255) PRIMARY KEY,
			CONSTRAINT fk_iss_cred FOREIGN KEY(id) REFERENCES verifiable_credentials(id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS received_verifiable_credentials (
			id VARCHAR(255) PRIMARY KEY,
			CONSTRAINT fk_recv_cred FOREIGN KEY(id) REFERENCES verifiable_credentials(id) ON DELETE CASCADE
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

func (s SQLCredentialStore) StoreCredential(credential vc.VerifiableCredential) error {
	// Collect data to be stored
	data, _ := credential.MarshalJSON()
	credentialSubject, err := s.getCredentialSubject(credential)
	if err != nil {
		return fmt.Errorf("failed to make indexable credential subject (id=%s): %w", credential.ID, err)
	}
	credentialSubjectJSON, _ := json.Marshal(credentialSubject)

	var credentialTypes []string
	for _, t := range credential.Type {
		credentialTypes = append(credentialTypes, t.String())
	}

	return storage.DoSqlTx(s.db, func(tx *sql.Tx) error {
		query := fmt.Sprintf("SELECT COUNT(id) FROM %s WHERE id = $1", s.tableName())
		if exists, err := queryExists(tx, query, credential.ID.String()); err != nil {
			return fmt.Errorf("failed to check if credential (%s) exists (id=%s): %w", s.tableName(), credential.ID, err)
		} else if exists {
			// already exists
			return nil
		}

		if exists, err := queryExists(tx, "SELECT COUNT(id) FROM verifiable_credentials WHERE id = $1", credential.ID.String()); err != nil {
			return fmt.Errorf("failed to check if credential exists (id=%s): %w", credential.ID, err)
		} else if exists {
			// already exists
			return nil
		}

		_, err = tx.Exec("INSERT INTO verifiable_credentials (id, issuer, type, subject_json, data) VALUES ($1, $2, $3, $4, $5)",
			credential.ID.String(), credential.Issuer.String(), pq.Array(credentialTypes), credentialSubjectJSON, data)
		if err != nil {
			return fmt.Errorf("failed to store credential (id=%s): %w", credential.ID, err)
		}
		tableName := s.tableName()
		_, err = tx.Exec(fmt.Sprintf("INSERT INTO %s (id) VALUES ($1)", tableName), credential.ID.String())
		if err != nil {
			return fmt.Errorf("failed to store credential (id=%s): %w", credential.ID, err)
		}
		return nil
	})
}

func (s SQLCredentialStore) GetCredential(id ssi.URI) (*vc.VerifiableCredential, error) {
	credentials, err := s.SearchCredentials(vc.VerifiableCredential{ID: &id}, false)
	if err != nil {
		return nil, err
	}
	if len(credentials) == 0 {
		return nil, types.ErrNotFound
	}
	// ID is unique, so there will only be 1 result
	return &credentials[0], err
}

func (s SQLCredentialStore) SearchCredentials(credentialQuery vc.VerifiableCredential, filterOnType bool) ([]vc.VerifiableCredential, error) {
	query := fmt.Sprintf(
		"SELECT cred.id, cred.data "+
			"FROM %s t1 "+
			"INNER JOIN verifiable_credentials cred "+
			"ON t1.id = cred.id "+
			"WHERE ", s.tableName())

	whereClauses, args, err := s.buildWhereClauses(credentialQuery, filterOnType)
	if err != nil {
		return nil, err
	}
	if len(whereClauses) == 0 {
		return nil, fmt.Errorf("no credential search parameters provided")
	}

	query += strings.Join(whereClauses, " AND ")

	log.Logger().Tracef("Executing credential SQL query: %s", query)
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to search for credentials: %w", err)
	}
	return s.readResults(rows)
}

func (s SQLCredentialStore) Count() (int, error) {
	var count int
	err := s.db.QueryRow(fmt.Sprintf("SELECT COUNT(t.id) "+
		"FROM %s t "+
		"INNER JOIN verifiable_credentials r ON t.id = r.id", s.tableName())).Scan(&count)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	return count, nil
}

func (s SQLCredentialStore) buildWhereClauses(credentialQuery vc.VerifiableCredential, filterOnType bool) ([]string, []interface{}, error) {
	var whereClauses []string
	var args []interface{}

	// Search on ID (would yield just 1 result)?
	if credentialQuery.ID != nil && credentialQuery.ID.String() != "" {
		whereClauses = append(whereClauses, fmt.Sprintf("cred.id = $%d", len(args)+1))
		args = append(args, credentialQuery.ID.String())
		// IDs are unique, no need for other WHERE clauses
		return whereClauses, args, nil
	}

	// Search on issuer
	if credentialQuery.Issuer.String() != "" {
		whereClauses = append(whereClauses, fmt.Sprintf("cred.issuer = $%d", len(args)+1))
		args = append(args, credentialQuery.Issuer.String())
	}

	// Search on credential type
	if len(credentialQuery.Type) > 0 && filterOnType {
		var credentialTypes []string
		for _, curr := range credentialQuery.Type {
			credentialTypes = append(credentialTypes, curr.String())
		}
		whereClauses = append(whereClauses, fmt.Sprintf("cred.type @> $%d", len(args)+1))
		args = append(args, pq.Array(credentialTypes))
	}

	// Search on subject
	if credentialQuery.CredentialSubject != nil {
		expandedQuery, err := s.expandJSONLDDocument(credentialQuery)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to JSON-LD expand query: %w", err)
		}
		removeEmptyAtIDFromDocument(expandedQuery)
		queryDocument, err := s.getCredentialSubjectFromDocument(expandedQuery)
		// Full-text search needs to be used in case a wildcard (*) is used. Only prefix matching (e.g. Hospit*) is supported.
		// Can possibly be implemented using tsvector, but can't get my head around that.
		// Using JSONB query instead, which might be slower(?), but works.
		// For instance:
		// select subject_json,
		//       subject_json::jsonb->0->'http://schema.org/organization'->0->'http://schema.org/legalname'->0->>'@value' LIKE 'Hospit%'
		// from verifiable_credentials;
		fullTextClauses, fullTextClauseValues := applyFullTextSearch("subject_json::jsonb", queryDocument)
		for i := 0; i < len(fullTextClauses); i++ {
			value := fullTextClauseValues[i]
			if len(value) == 0 {
				// NOT NULL clause
				whereClauses = append(whereClauses, fullTextClauses[i])
			} else {
				// LIKE clause
				// Just have to add arg indexer ($1, $2, etc.) to the clause
				whereClauses = append(whereClauses, fullTextClauses[i]+" $"+strconv.Itoa(len(args)+1))
				args = append(args, value)
			}
		}
		// TODO: check if there were only full-text clauses, in that case we must not add the subject_json clause
		whereClauses = append(whereClauses, fmt.Sprintf("cred.subject_json @> $%d", len(args)+1))
		subjectQueryJSON, _ := json.Marshal(queryDocument)
		args = append(args, subjectQueryJSON)
	}
	return whereClauses, args, nil
}

func (s SQLCredentialStore) readResults(rows *sql.Rows) ([]vc.VerifiableCredential, error) {
	var results []vc.VerifiableCredential
	for rows.Next() {
		var id string
		var data []byte
		err := rows.Scan(&id, &data)
		if err != nil {
			return nil, fmt.Errorf("failed to get results: %w", err)
		}

		var result vc.VerifiableCredential
		err = json.Unmarshal(data, &result)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal credential (id=%s): %w", id, err)
		}
		results = append(results, result)
	}
	return results, nil
}

func (s SQLCredentialStore) tableName() string {
	var tableName string
	if s.role == RoleIssuer {
		tableName = "issued_verifiable_credentials"
	} else {
		tableName = "received_verifiable_credentials"
	}
	return tableName
}

func (s SQLCredentialStore) getCredentialSubject(credential vc.VerifiableCredential) (interface{}, error) {
	document, err := s.expandJSONLDDocument(credential)
	if err != nil {
		return nil, err
	}
	return s.getCredentialSubjectFromDocument(document)
}

func (s SQLCredentialStore) getCredentialSubjectFromDocument(credentialAsDocument jsonld.Document) (interface{}, error) {
	if len(credentialAsDocument) < 1 {
		return nil, nil
	}
	item, ok := credentialAsDocument[0].(map[string]interface{})
	if !ok {
		return nil, nil
	}
	return item["https://www.w3.org/2018/credentials#credentialSubject"], nil
}

func (s SQLCredentialStore) expandJSONLDDocument(document interface{}) (jsonld.Document, error) {
	reader := jsonld.Reader{
		DocumentLoader:           s.documentLoader,
		AllowUndefinedProperties: true,
	}
	expandedDocument, err := reader.Read(document)
	if err != nil {
		return nil, err
	}
	if len(expandedDocument) != 1 {
		return nil, fmt.Errorf("expected 1 document entry, got %d", len(expandedDocument))
	}
	return expandedDocument, nil
}

func removeEmptyAtIDFromDocument(input interface{}) {
	switch document := input.(type) {
	case jsonld.Document:
		for _, value := range document {
			removeEmptyAtIDFromDocument(value)
		}
	case []interface{}:
		for _, value := range document {
			removeEmptyAtIDFromDocument(value)
		}
	case map[string]interface{}:
		for key, value := range document {
			if key == "@id" && value == "" {
				delete(document, key)
			} else {
				removeEmptyAtIDFromDocument(value)
			}
		}
	}
}

// likeClause is a clause that can be used in a LIKE query for querying JSONB columns. Examples:
// ->0->'http://schema.org/organization'->0->'http://schema.org/legalname'->0->>'@value' LIKE 'Hospit%'
// ->0->'http://schema.org/organization'->0->'http://schema.org/legalname'->0->>'@value' IS NOT NULL
type likeClause struct {
	path []interface{}
	// value is the value to match against, can contain a wildcard (%) at the end.
	// If the value is empty, the clause is a NOT NULL clause
	value string
}

func applyFullTextSearch(prefix string, document interface{}) ([]string, []string) {
	clauses := flatten(document, nil)
	paths := make([]string, 0)
	values := make([]string, 0)

	for _, clause := range clauses {
		path := prefix
		for _, pathPart := range clause.path {
			indexerPart, isIndexed := pathPart.(int)
			if isIndexed {
				path += "->" + strconv.Itoa(indexerPart)
			} else if pathPart == "@value" {
				// value must be taken as text, otherwise LIKE will error
				path += "->>'" + pathPart.(string) + "'"
			} else {
				path += "->'" + pathPart.(string) + "'"
			}
		}
		if len(clause.value) == 0 {
			path += " IS NOT NULL"
		} else {
			path += " LIKE"
		}
		paths = append(paths, path)
		values = append(values, clause.value)
		println(path, "=", clause.value)
	}
	return paths, values
}

func flatten(document interface{}, currentPath []interface{}) []likeClause {
	switch typedDocument := document.(type) {
	case jsonld.Document:
		return flattenSlice(typedDocument, currentPath)
	case []interface{}:
		return flattenSlice(typedDocument, currentPath)
	case map[string]interface{}:
		return flattenMap(typedDocument, currentPath)
	}
	return nil
}

func flattenSlice(expanded []interface{}, currentPath []interface{}) []likeClause {
	result := make([]likeClause, 0)
	for i, sub := range expanded {
		result = append(result, flatten(sub, append(currentPath, i))...)
	}
	return result
}

func flattenMap(expanded map[string]interface{}, currentPath []interface{}) []likeClause {
	// JSON-LD in expanded form either has @value, @id, @list or objects
	results := make([]likeClause, 0)
	for key, value := range expanded {
		switch key {
		case "@id":
			fallthrough
		case "@value":
			// prefix matching for strings when it ends with an asterisk (*)
			if valueString, ok := value.(string); ok {
				if strings.HasSuffix(valueString, "*") {
					// replace last * with %
					valueString = valueString[:len(valueString)-1] + "%"
					// search query with just * means: must be present, otherwise it's a prefix query
					results = append(results, likeClause{
						path:  append(currentPath, key),
						value: valueString,
					})
					// now delete the clause from the document since will be used as JSONB query,
					// but these LIKE clauses are not supported in JSONB
					delete(expanded, key)
				}
			}
		case "@list":
			results = append(results, flatten(value, currentPath)...)
		default:
			results = append(results, flatten(value, append(currentPath, key))...)
		}
	}

	return results
}
