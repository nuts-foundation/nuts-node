/*
 * Copyright (C) 2024 Nuts community
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

package store

import (
	"encoding/json"
	"fmt"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vcr/log"
	"gorm.io/gorm"
	"strconv"
	"strings"
)

// CredentialRecord is a Verifiable Credential stored in the SQL database.
type CredentialRecord struct {
	// ID contains the 'id' property of the Verifiable Credential.
	ID string
	// Issuer contains the 'issuer' property of the Verifiable Credential.
	Issuer string
	// SubjectID contains the 'credentialSubject.id' property of the Verifiable Credential.
	SubjectID string
	// Type contains the 'type' property of the Verifiable Credential (not being 'VerifiableCredential').
	Type *string
	// ExpirationDate is the credential's 'expirationDate' as seconds since Unix epoch. Credentials
	// without an expirationDate carry the neverExpires sentinel rather than NULL; NULL means the row
	// predates this column and has not been backfilled yet.
	ExpirationDate *int64 `gorm:"column:expiration_date"`
	// Raw contains the raw JSON of the Verifiable Credential.
	Raw        string
	Properties []CredentialPropertyRecord `gorm:"foreignKey:CredentialID;references:ID"`
}

// TableName returns the table name for this DTO.
func (p CredentialRecord) TableName() string {
	return "credential"
}

// CredentialPropertyRecord is a property of a Verifiable Credential stored in the SQL database.
type CredentialPropertyRecord struct {
	// CredentialID refers to the entry record in credential
	CredentialID string `gorm:"primaryKey"`
	// Path is JSON path of the property.
	Path string `gorm:"primaryKey"`
	// Value is the value of the property.
	Value string
}

// TableName returns the table name for this DTO.
func (l CredentialPropertyRecord) TableName() string {
	return "credential_prop"
}

// CredentialStore stores Verifiable Credentials in a SQL database.
type CredentialStore struct {
}

// Store stores a Verifiable Credential in the SQL database.
func (c CredentialStore) Store(db *gorm.DB, credential vc.VerifiableCredential) (*CredentialRecord, error) {
	subjectDID, err := credential.SubjectDID()
	if err != nil {
		return nil, fmt.Errorf("failed to extract subject DID: %w", err)
	}
	// Base properties
	newCredential := CredentialRecord{
		ID:        credential.ID.String(),
		Issuer:    credential.Issuer.String(),
		SubjectID: subjectDID.String(),
		Raw:       credential.Raw(),
	}
	// Set type
	for _, currType := range credential.Type {
		if currType.String() != "VerifiableCredential" {
			val := currType.String()
			newCredential.Type = &val
			break
		}
	}
	// Set expiration date (seconds since Unix epoch). Credentials without an expirationDate get the
	// neverExpires sentinel rather than NULL, so the backfill never has to revisit them.
	exp := neverExpires
	if credential.ExpirationDate != nil && !credential.ExpirationDate.IsZero() {
		exp = credential.ExpirationDate.Unix()
	}
	newCredential.ExpirationDate = &exp
	// Create key-value properties of the credential subject, which is then stored in the property table for searching.
	if len(credential.CredentialSubject) != 1 {
		return nil, fmt.Errorf("expected exactly one credential subject, got %d", len(credential.CredentialSubject))
	}
	credentialSubjectJSON, err := json.Marshal(credential.CredentialSubject[0])
	if err != nil {
		return nil, fmt.Errorf("failed to marshal credential subject: %w", err)
	}
	var credentialSubject map[string]interface{}
	_ = json.Unmarshal(credentialSubjectJSON, &credentialSubject) // if we marshalled it, we can unmarshal into a map
	// now index it
	paths, values := indexJSONObject(credentialSubject, nil, nil, "credentialSubject")
	for i, path := range paths {
		if path == "credentialSubject.id" {
			// present as column, don't index
			continue
		}
		newCredential.Properties = append(newCredential.Properties, CredentialPropertyRecord{
			CredentialID: newCredential.ID,
			Path:         path,
			Value:        values[i],
		})
	}

	var existingCredential *CredentialRecord
	if err := db.Where(CredentialRecord{ID: newCredential.ID}).
		Attrs(newCredential).
		FirstOrCreate(&existingCredential).Error; err != nil {
		return nil, err
	}
	// compare with all whitespace and linebreaks removed
	// todo: replace with correct canonicalization from VC spec, once it's available. Should be implemented in go-did.
	if stripWhitespaceAndLinebreaks(existingCredential.Raw) != stripWhitespaceAndLinebreaks(newCredential.Raw) {
		return nil, fmt.Errorf("credential with this ID already exists with different contents: %s", newCredential.ID)
	}
	return &newCredential, nil
}

// neverExpires is the expiration_date sentinel for credentials that have no expirationDate. Storing
// it instead of NULL lets BackfillExpirationDates run once and never revisit these rows on
// subsequent startups (NULL means "stored before this column existed, not yet backfilled"). The
// value is 9999-12-31T23:59:59Z, far enough in the future that the "expiring within X" range query
// never matches it, so a never-expiring credential is correctly excluded without query special-casing.
//
// TODO: remove together with BackfillExpirationDates in v7. v7+ stores can map "no expirationDate"
// back to NULL directly; a migration may NULL out any remaining sentinels.
const neverExpires int64 = 253402300799

// BackfillExpirationDates populates the expiration_date column for credentials stored before the
// column existed, by parsing each credential whose column is still NULL and writing its expiration
// (or the neverExpires sentinel when it has none). Updates are batched in transactions of
// backfillBatchSize.
//
// Every NULL row must be parsed: a JWT-encoded credential keeps its expiry in a base64 `exp` claim
// that no SQL text filter can match, so there is no cheap way to pre-select only rows that have an
// expiration. Because each processed row is written to a non-NULL value (real date or sentinel), it
// drops out of the NULL set, so the backfill is effectively one-shot — after the first run only
// rows that fail to parse (which shouldn't happen) remain NULL.
//
// Pagination uses the id as a keyset cursor rather than relying on updated rows leaving the result
// set, so unparseable rows that stay NULL don't stall the walk.
//
// TODO: remove in v7 — by then all v6 nodes will have backfilled their existing rows, and v7+
// stores populate expiration_date directly on Store().
func BackfillExpirationDates(db *gorm.DB) error {
	const backfillBatchSize = 500
	lastID := ""
	for {
		var records []CredentialRecord
		err := db.Model(&CredentialRecord{}).
			Where("expiration_date IS NULL AND id > ?", lastID).
			Order("id").
			Limit(backfillBatchSize).
			Find(&records).Error
		if err != nil {
			return fmt.Errorf("backfill expiration_date: query: %w", err)
		}
		if len(records) == 0 {
			return nil
		}
		err = db.Transaction(func(tx *gorm.DB) error {
			for _, record := range records {
				parsed, err := vc.ParseVerifiableCredential(record.Raw)
				if err != nil {
					// Unparseable raw blob shouldn't happen — Store() parsed it before persisting.
					// Skip rather than abort the whole backfill, but warn so it's investigatable.
					log.Logger().
						WithError(err).
						WithField(core.LogFieldCredentialID, record.ID).
						Warn("backfill expiration_date: unable to parse stored credential")
					continue
				}
				exp := neverExpires
				if parsed.ExpirationDate != nil && !parsed.ExpirationDate.IsZero() {
					exp = parsed.ExpirationDate.Unix()
				}
				if err := tx.Model(&CredentialRecord{}).
					Where("id = ?", record.ID).
					Update("expiration_date", exp).Error; err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("backfill expiration_date: update: %w", err)
		}
		lastID = records[len(records)-1].ID
		if len(records) < backfillBatchSize {
			return nil
		}
	}
}

// stripWhitespaceAndLinebreaks removes all whitespace and linebreaks from a string.
func stripWhitespaceAndLinebreaks(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, " ", ""), "\n", "")
}

// BuildSearchStatement enriches a Gorm query to search for Verifiable Credentials in the SQL database.
// The db instance must a Gorm query builder which determines the model and subset of credentials to search in
// using a JOIN or WHERE clause, e.g.:
// var results []issuedCredential
// CredentialStore.BuildSearchStatement(
//
//	db.Model(&issuedCredential{}).Where("issuer = ?", issuer),
//	"issued_credential.credential_id",
//	query,
//
// ).Find(&results)
// In this case, issuedCredential must have a Credential field of type CredentialRecord, which can be mapped by Gorm.
func (c CredentialStore) BuildSearchStatement(db *gorm.DB, onClauseColumn string, query map[string]string) *gorm.DB {
	propertyColumns := map[string]string{
		"id":                   "credential.id",
		"issuer":               "credential.issuer",
		"type":                 "credential.type",
		"credentialSubject.id": "credential.subject_id",
	}

	stmt := db.Joins("inner join credential ON credential.id = " + onClauseColumn)
	numProps := 0
	for jsonPath, value := range query {
		if value == "*" {
			continue
		}
		// sort out wildcard mode: prefix and postfix asterisks (*) are replaced with %, which then is used in a LIKE query.
		// Otherwise, exact match (=) is used.
		var eq = "="
		if strings.HasPrefix(value, "*") {
			value = "%" + value[1:]
			eq = "LIKE"
		}
		if strings.HasSuffix(value, "*") {
			value = value[:len(value)-1] + "%"
			eq = "LIKE"
		}
		if column := propertyColumns[jsonPath]; column != "" {
			stmt = stmt.Where(column+" "+eq+" ?", value)
		} else {
			// This property is not present as column, but indexed as key-value property.
			// Multiple (inner) joins to filter on a dynamic number of properties to filter on is not pretty, but it works
			alias := "p" + strconv.Itoa(numProps)
			numProps++
			stmt = stmt.Joins("inner join credential_prop "+alias+" ON "+alias+".credential_id = credential.id AND "+alias+".path = ? AND "+alias+".value "+eq+" ?", jsonPath, value)
		}
	}
	return stmt
}

// indexJSONObject indexes a JSON object, resulting in a slice of JSON paths and corresponding string values.
// It only traverses JSON objects and only adds string values to the result.
func indexJSONObject(target map[string]interface{}, jsonPaths []string, stringValues []string, currentPath string) ([]string, []string) {
	for path, value := range target {
		thisPath := currentPath
		if len(thisPath) > 0 {
			thisPath += "."
		}
		thisPath += path

		switch typedValue := value.(type) {
		case string:
			jsonPaths = append(jsonPaths, thisPath)
			stringValues = append(stringValues, typedValue)
		case map[string]interface{}:
			jsonPaths, stringValues = indexJSONObject(typedValue, jsonPaths, stringValues, thisPath)
		default:
			// other values (arrays, booleans, numbers, null) are not indexed
		}
	}
	return jsonPaths, stringValues
}
