/*
 * Copyright (C) 2023 Nuts community
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

package discoveryservice

import (
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/discoveryservice/log"
	credential "github.com/nuts-foundation/nuts-node/vcr/credential"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/schema"
	"strconv"
	"strings"
	"time"
)

var ErrServiceNotFound = errors.New("discovery service not found")
var ErrPresentationAlreadyExists = errors.New("presentation already exists")

type serviceRecord struct {
	ID        string `gorm:"primaryKey"`
	Timestamp uint64
}

func (s serviceRecord) TableName() string {
	return "discoveryservices"
}

var _ schema.Tabler = (*presentationRecord)(nil)

type presentationRecord struct {
	ID                     string `gorm:"primaryKey"`
	ServiceID              string
	Timestamp              uint64
	CredentialSubjectID    string
	PresentationID         string
	PresentationRaw        string
	PresentationExpiration int64
	Credentials            []credentialRecord `gorm:"foreignKey:PresentationID;references:ID"`
}

func (s presentationRecord) TableName() string {
	return "discoveryservice_presentations"
}

// credentialRecord is a Verifiable Credential, part of a presentation (entry) on a use case list.
type credentialRecord struct {
	// ID is the unique identifier of the entry.
	ID string `gorm:"primaryKey"`
	// PresentationID corresponds to the discoveryservice_presentations record ID (not VerifiablePresentation.ID) this credentialRecord belongs to.
	PresentationID string
	// CredentialID contains the 'id' property of the Verifiable Credential.
	CredentialID string
	// CredentialIssuer contains the 'issuer' property of the Verifiable Credential.
	CredentialIssuer string
	// CredentialSubjectID contains the 'credentialSubject.id' property of the Verifiable Credential.
	CredentialSubjectID string
	// CredentialType contains the 'type' property of the Verifiable Credential (not being 'VerifiableCredential').
	CredentialType *string
	Properties     []credentialPropertyRecord `gorm:"foreignKey:ID;references:ID"`
}

// TableName returns the table name for this DTO.
func (p credentialRecord) TableName() string {
	return "discoveryservice_credentials"
}

// credentialPropertyRecord is a property of a Verifiable Credential in a Verifiable Presentation in a discovery service.
type credentialPropertyRecord struct {
	// ID refers to the entry record in discoveryservice_credentials
	ID string `gorm:"primaryKey"`
	// Key is JSON path of the property.
	Key string `gorm:"primaryKey"`
	// Value is the value of the property.
	Value string
}

// TableName returns the table name for this DTO.
func (l credentialPropertyRecord) TableName() string {
	return "discoveryservice_credential_props"
}

type sqlStore struct {
	db *gorm.DB
}

func newSQLStore(db *gorm.DB, definitions map[string]Definition) (*sqlStore, error) {
	// Creates entries in the discovery service table with initial timestamp, if they don't exist yet
	for _, definition := range definitions {
		currentList := serviceRecord{
			ID: definition.ID,
		}
		if err := db.FirstOrCreate(&currentList, "id = ?", definition.ID).Error; err != nil {
			return nil, err
		}
	}
	return &sqlStore{
		db: db,
	}, nil
}

// Add adds a presentation to the list of presentations.
// Timestamp should be passed if the presentation was received from a remote Discovery Server, then it is stored alongside the presentation.
// If the local node is the Discovery Server and thus is responsible for the timestamping,
// nil should be passed to let the store determine the right value.
func (s *sqlStore) add(serviceID string, presentation vc.VerifiablePresentation, timestamp *Timestamp) error {
	credentialSubjectID, err := credential.PresentationSigner(presentation)
	if err != nil {
		return err
	}
	if exists, err := s.exists(serviceID, credentialSubjectID.String(), presentation.ID.String()); err != nil {
		return err
	} else if exists {
		return ErrPresentationAlreadyExists
	}
	if err := s.prune(); err != nil {
		return err
	}

	return s.db.Transaction(func(tx *gorm.DB) error {
		newTimestamp, err := s.updateTimestamp(tx, serviceID, timestamp)
		if err != nil {
			return err
		}
		// Delete any previous presentations of the subject
		if err := tx.Delete(&presentationRecord{}, "service_id = ? AND credential_subject_id = ?", serviceID, credentialSubjectID.String()).
			Error; err != nil {
			return err
		}

		newPresentation, err := createPresentationRecord(serviceID, newTimestamp, presentation)
		if err != nil {
			return err
		}

		return tx.Create(&newPresentation).Error
	})
}

// createPresentationRecord creates a presentationRecord from a VerifiablePresentation.
// It creates the following types:
// - presentationRecord
// - presentationRecord.Credentials with credentialRecords of the credentials in the presentation
// - presentationRecord.Credentials.Properties of the credentialSubject properties of the credential (for s
func createPresentationRecord(serviceID string, timestamp Timestamp, presentation vc.VerifiablePresentation) (*presentationRecord, error) {
	credentialSubjectID, err := credential.PresentationSigner(presentation)
	if err != nil {
		return nil, err
	}

	newPresentation := presentationRecord{
		ID:                     uuid.NewString(),
		ServiceID:              serviceID,
		Timestamp:              uint64(timestamp),
		CredentialSubjectID:    credentialSubjectID.String(),
		PresentationID:         presentation.ID.String(),
		PresentationRaw:        presentation.Raw(),
		PresentationExpiration: presentation.JWT().Expiration().Unix(),
	}

	for _, currCred := range presentation.VerifiableCredential {
		var credentialType *string
		for _, currType := range currCred.Type {
			if currType.String() != "VerifiableCredential" {
				credentialType = new(string)
				*credentialType = currType.String()
				break
			}
		}
		if len(currCred.CredentialSubject) != 1 {
			return nil, errors.New("credential must contain exactly one subject")
		}

		newCredential := credentialRecord{
			ID:                  uuid.NewString(),
			PresentationID:      newPresentation.ID,
			CredentialID:        currCred.ID.String(),
			CredentialIssuer:    currCred.Issuer.String(),
			CredentialSubjectID: credentialSubjectID.String(),
			CredentialType:      credentialType,
		}
		// Store credential's properties
		keys, values := indexJSONObject(currCred.CredentialSubject[0].(map[string]interface{}), nil, nil, "credentialSubject")
		for i, key := range keys {
			if key == "credentialSubject.id" {
				// present as column, don't index
				continue
			}
			newCredential.Properties = append(newCredential.Properties, credentialPropertyRecord{
				ID:    newCredential.ID,
				Key:   key,
				Value: values[i],
			})
		}
		newPresentation.Credentials = append(newPresentation.Credentials, newCredential)
	}
	return &newPresentation, nil
}

func (s *sqlStore) get(serviceID string, startAt Timestamp) ([]vc.VerifiablePresentation, *Timestamp, error) {
	var rows []presentationRecord
	err := s.db.Order("timestamp ASC").Find(&rows, "service_id = ? AND timestamp > ?", serviceID, int(startAt)).Error
	if err != nil {
		return nil, nil, fmt.Errorf("query service '%s': %w", serviceID, err)
	}
	timestamp := startAt
	presentations := make([]vc.VerifiablePresentation, 0, len(rows))
	for _, row := range rows {
		presentation, err := vc.ParseVerifiablePresentation(row.PresentationRaw)
		if err != nil {
			return nil, nil, fmt.Errorf("parse presentation '%s' of service '%s': %w", row.PresentationID, serviceID, err)
		}
		presentations = append(presentations, *presentation)
		timestamp = Timestamp(row.Timestamp)
	}
	return presentations, &timestamp, nil
}

func (s *sqlStore) search(serviceID string, query map[string]string) ([]vc.VerifiablePresentation, error) {
	propertyColumns := map[string]string{
		"id":                   "cred.credential_id",
		"issuer":               "cred.credential_issuer",
		"type":                 "cred.credential_type",
		"credentialSubject.id": "cred.credential_subject_id",
	}

	stmt := s.db.Model(&presentationRecord{}).
		Where("service_id = ?", serviceID).
		Joins("inner join discoveryservice_credentials cred ON cred.presentation_id = discoveryservice_presentations.id")
	numProps := 0
	for jsonPath, value := range query {
		if value == "*" {
			continue
		}
		// sort out wildcard mode
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
			stmt = stmt.Joins("inner join discoveryservice_credential_props "+alias+" ON "+alias+".id = cred.id AND "+alias+".key = ? AND "+alias+".value "+eq+" ?", jsonPath, value)
		}
	}

	var matches []presentationRecord
	if err := stmt.Find(&matches).Error; err != nil {
		return nil, err
	}
	var results []vc.VerifiablePresentation
	for _, match := range matches {
		if match.PresentationExpiration <= time.Now().Unix() {
			continue
		}
		presentation, err := vc.ParseVerifiablePresentation(match.PresentationRaw)
		if err != nil {
			return nil, fmt.Errorf("failed to parse presentation '%s': %w", match.PresentationID, err)
		}
		results = append(results, *presentation)
	}
	return results, nil
}

func (s *sqlStore) updateTimestamp(tx *gorm.DB, serviceID string, newTimestamp *Timestamp) (Timestamp, error) {
	var result serviceRecord
	// Lock (SELECT FOR UPDATE) discoveryservices row to prevent concurrent updates to the same list, which could mess up the lamport timestamp.
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
		Where(serviceRecord{ID: serviceID}).
		Find(&result).
		Error; err != nil {
		return 0, err
	}
	result.ID = serviceID
	if newTimestamp == nil {
		// Increment timestamp
		result.Timestamp++
	} else {
		result.Timestamp = uint64(*newTimestamp)
	}
	if err := tx.Save(&result).Error; err != nil {
		return 0, err
	}
	return Timestamp(result.Timestamp), nil
}

func (s *sqlStore) exists(serviceID string, credentialSubjectID string, presentationID string) (bool, error) {
	var count int64
	if err := s.db.Model(presentationRecord{}).Where(presentationRecord{
		ServiceID:           serviceID,
		CredentialSubjectID: credentialSubjectID,
		PresentationID:      presentationID,
	}).Count(&count).Error; err != nil {
		return false, fmt.Errorf("check presentation existence: %w", err)
	}
	return count > 0, nil
}

func (s *sqlStore) prune() error {
	num, err := s.removeExpired()
	if err != nil {
		return err
	}
	if num > 0 {
		log.Logger().Debugf("Pruned %d expired presentations", num)
	}
	return nil
}

func (s *sqlStore) removeExpired() (int, error) {
	result := s.db.Where("presentation_expiration < ?", time.Now().Unix()).Delete(presentationRecord{})
	if result.Error != nil {
		return 0, fmt.Errorf("prune presentations: %w", result.Error)
	}
	return int(result.RowsAffected), nil
}

// indexJSONObject indexes a JSON object, resulting in a slice of JSON paths and corresponding string values.
// It only traverses JSON objects and only adds string values to the result.
func indexJSONObject(target map[string]interface{}, jsonPaths []string, stringValues []string, currentPath string) ([]string, []string) {
	for key, value := range target {
		thisPath := currentPath
		if len(thisPath) > 0 {
			thisPath += "."
		}
		thisPath += key

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
