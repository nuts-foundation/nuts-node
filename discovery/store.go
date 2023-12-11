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

package discovery

import (
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/discovery/log"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/schema"
	"math/rand"
	"strconv"
	"strings"
	"sync"
	"time"
)

const tagPrefixLength = 5

type serviceRecord struct {
	ID        string `gorm:"primaryKey"`
	LastTag   Tag
	TagPrefix string
}

func (s serviceRecord) TableName() string {
	return "discovery_service"
}

var _ schema.Tabler = (*presentationRecord)(nil)

type presentationRecord struct {
	ID                     string `gorm:"primaryKey"`
	ServiceID              string
	LamportTimestamp       uint64
	CredentialSubjectID    string
	PresentationID         string
	PresentationRaw        string
	PresentationExpiration int64
	Credentials            []credentialRecord `gorm:"foreignKey:PresentationID;references:ID"`
}

func (s presentationRecord) TableName() string {
	return "discovery_presentation"
}

// credentialRecord is a Verifiable Credential, part of a presentation (entry) on a use case list.
type credentialRecord struct {
	// ID is the unique identifier of the entry.
	ID string `gorm:"primaryKey"`
	// PresentationID corresponds to the discovery_presentation record ID (not VerifiablePresentation.ID) this credentialRecord belongs to.
	PresentationID string
	// CredentialID contains the 'id' property of the Verifiable Credential.
	CredentialID string
	// CredentialIssuer contains the 'issuer' property of the Verifiable Credential.
	CredentialIssuer string
	// CredentialSubjectID contains the 'credentialSubject.id' property of the Verifiable Credential.
	CredentialSubjectID string
	// CredentialType contains the 'type' property of the Verifiable Credential (not being 'VerifiableCredential').
	CredentialType *string
	Properties     []credentialPropertyRecord `gorm:"foreignKey:CredentialID;references:ID"`
}

// TableName returns the table name for this DTO.
func (p credentialRecord) TableName() string {
	return "discovery_credential"
}

// credentialPropertyRecord is a property of a Verifiable Credential in a Verifiable Presentation in a discovery service.
type credentialPropertyRecord struct {
	// CredentialID refers to the entry record in discovery_credential
	CredentialID string `gorm:"primaryKey"`
	// Key is JSON path of the property.
	Key string `gorm:"primaryKey"`
	// Value is the value of the property.
	Value string
}

// TableName returns the table name for this DTO.
func (l credentialPropertyRecord) TableName() string {
	return "discovery_credential_prop"
}

type sqlStore struct {
	db        *gorm.DB
	writeLock sync.Mutex
}

func newSQLStore(db *gorm.DB, clientDefinitions map[string]ServiceDefinition, serverDefinitions map[string]ServiceDefinition) (*sqlStore, error) {
	// Creates entries in the discovery service table, if they don't exist yet
	for _, definition := range clientDefinitions {
		currentList := serviceRecord{
			ID: definition.ID,
		}
		// If the node is server for this discovery service, make sure the timestamp prefix is set.
		if _, isServer := serverDefinitions[definition.ID]; isServer {
			currentList.TagPrefix = generatePrefix()
		}
		if err := db.FirstOrCreate(&currentList, "id = ?", definition.ID).Error; err != nil {
			return nil, err
		}
	}
	return &sqlStore{
		db:        db,
		writeLock: sync.Mutex{},
	}, nil
}

// Add adds a presentation to the list of presentations.
// Tag should be passed if the presentation was received from a remote Discovery Server, then it is stored alongside the presentation.
// If the local node is the Discovery Server and thus is responsible for the timestamping,
// nil should be passed to let the store determine the right value.
func (s *sqlStore) add(serviceID string, presentation vc.VerifiablePresentation, tag *Tag) error {
	credentialSubjectID, err := credential.PresentationSigner(presentation)
	if err != nil {
		return err
	}
	if _, isSQLite := s.db.Config.Dialector.(*sqlite.Dialector); isSQLite {
		// SQLite does not support SELECT FOR UPDATE and allows only 1 active write transaction at any time,
		// and any other attempt to acquire a write transaction will directly return an error.
		// This is in contrast to most other SQL-databases, which let the 2nd thread wait for some time to acquire the lock.
		// The general advice for SQLite is to retry the operation, which is just poor-man's scheduling.
		// So to keep behavior consistent across databases, we'll just lock the entire store for the duration of the transaction.
		// See https://github.com/nuts-foundation/nuts-node/pull/2589#discussion_r1399130608
		s.writeLock.Lock()
		defer s.writeLock.Unlock()
	}
	if err := s.prune(); err != nil {
		return err
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		newTimestamp, err := s.updateTag(tx, serviceID, tag)
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
func createPresentationRecord(serviceID string, timestamp *Timestamp, presentation vc.VerifiablePresentation) (*presentationRecord, error) {
	credentialSubjectID, err := credential.PresentationSigner(presentation)
	if err != nil {
		return nil, err
	}

	newPresentation := presentationRecord{
		ID:                     uuid.NewString(),
		ServiceID:              serviceID,
		CredentialSubjectID:    credentialSubjectID.String(),
		PresentationID:         presentation.ID.String(),
		PresentationRaw:        presentation.Raw(),
		PresentationExpiration: presentation.JWT().Expiration().Unix(),
	}
	if timestamp != nil {
		newPresentation.LamportTimestamp = uint64(*timestamp)
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
		// Create key-value properties of the credential subject, which is then stored in the property table for searching.
		keys, values := indexJSONObject(currCred.CredentialSubject[0].(map[string]interface{}), nil, nil, "credentialSubject")
		for i, key := range keys {
			if key == "credentialSubject.id" {
				// present as column, don't index
				continue
			}
			newCredential.Properties = append(newCredential.Properties, credentialPropertyRecord{
				CredentialID: newCredential.ID,
				Key:          key,
				Value:        values[i],
			})
		}
		newPresentation.Credentials = append(newPresentation.Credentials, newCredential)
	}
	return &newPresentation, nil
}

// get returns all presentations, registered on the given service, starting after the given tag.
// It also returns the latest tag of the returned presentations.
// This tag can then be used next time to only retrieve presentations that were added after that tag.
func (s *sqlStore) get(serviceID string, tag *Tag) ([]vc.VerifiablePresentation, *Tag, error) {
	var service serviceRecord
	if err := s.db.Find(&service, "id = ?", serviceID).Error; err != nil {
		return nil, nil, fmt.Errorf("query service '%s': %w", serviceID, err)
	}
	var startAfter uint64
	if tag != nil {
		// Decode tag
		lamportTimestamp := tag.Timestamp(service.TagPrefix)
		if lamportTimestamp != nil {
			startAfter = uint64(*lamportTimestamp)
		}
	}

	var rows []presentationRecord
	err := s.db.Order("lamport_timestamp ASC").Find(&rows, "service_id = ? AND lamport_timestamp > ?", serviceID, startAfter).Error
	if err != nil {
		return nil, nil, fmt.Errorf("query service '%s': %w", serviceID, err)
	}
	presentations := make([]vc.VerifiablePresentation, 0, len(rows))
	for _, row := range rows {
		presentation, err := vc.ParseVerifiablePresentation(row.PresentationRaw)
		if err != nil {
			return nil, nil, fmt.Errorf("parse presentation '%s' of service '%s': %w", row.PresentationID, serviceID, err)
		}
		presentations = append(presentations, *presentation)
	}
	lastTag := service.LastTag
	if lastTag.Empty() {
		// Make sure we don't return an empty string for the tag, instead return tag indicating the beginning of the list.
		lastTag = Timestamp(0).Tag(service.TagPrefix)
	}
	return presentations, &lastTag, nil
}

// search searches for presentations, registered on the given service, matching the given query.
// The query is a map of JSON paths and expected string values, matched against the presentation's credentials.
// Wildcard matching is supported by prefixing or suffixing the value with an asterisk (*).
// It returns the presentations which contain credentials that match the given query.
func (s *sqlStore) search(serviceID string, query map[string]string) ([]vc.VerifiablePresentation, error) {
	propertyColumns := map[string]string{
		"id":                   "cred.credential_id",
		"issuer":               "cred.credential_issuer",
		"type":                 "cred.credential_type",
		"credentialSubject.id": "cred.credential_subject_id",
	}

	stmt := s.db.Model(&presentationRecord{}).
		Where("service_id = ?", serviceID).
		Joins("inner join discovery_credential cred ON cred.presentation_id = discovery_presentation.id")
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
			stmt = stmt.Joins("inner join discovery_credential_prop "+alias+" ON "+alias+".credential_id = cred.id AND "+alias+".key = ? AND "+alias+".value "+eq+" ?", jsonPath, value)
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

// updateTag updates the tag of the given service.
// Clients should pass the tag they received from the server (which simply sets it).
// Servers should pass nil (since they "own" the tag), which causes it to be incremented.
// It returns
func (s *sqlStore) updateTag(tx *gorm.DB, serviceID string, newTimestamp *Tag) (*Timestamp, error) {
	var service serviceRecord
	// Lock (SELECT FOR UPDATE) discovery_service row to prevent concurrent updates to the same list, which could mess up the lamport timestamp.
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
		Where(serviceRecord{ID: serviceID}).
		Find(&service).
		Error; err != nil {
		return nil, err
	}
	service.ID = serviceID
	var result *Timestamp
	if newTimestamp == nil {
		// Update tag: decode current timestamp, increment it, encode it again.
		currTimestamp := Timestamp(0)
		if service.LastTag != "" {
			// If LastTag is empty, it means the service was just created and no presentations were added yet.
			ts := service.LastTag.Timestamp(service.TagPrefix)
			if ts == nil {
				// would be very weird
				return nil, fmt.Errorf("invalid tag '%s'", service.LastTag)
			}
			currTimestamp = *ts
		}
		ts := currTimestamp.Increment()
		result = &ts
		service.LastTag = ts.Tag(service.TagPrefix)
	} else {
		// Set tag: just store it
		service.LastTag = *newTimestamp
	}
	if err := tx.Save(service).Error; err != nil {
		return nil, err
	}
	return result, nil
}

// exists checks whether a presentation of the given subject is registered on a service.
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

// generatePrefix generates a random seed for a service, consisting of 5 uppercase letters.
func generatePrefix() string {
	result := make([]byte, tagPrefixLength)
	lower := int('A')
	upper := int('Z')
	for i := 0; i < len(result); i++ {
		result[i] = byte(lower + rand.Intn(upper-lower))
	}
	return string(result)
}
