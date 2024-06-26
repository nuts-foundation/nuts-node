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
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/vcr/credential/store"
	"time"

	"github.com/google/uuid"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/discovery/log"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/schema"
)

type serviceRecord struct {
	ID                   string `gorm:"primaryKey"`
	LastLamportTimestamp int
}

func (s serviceRecord) TableName() string {
	return "discovery_service"
}

var _ schema.Tabler = (*presentationRecord)(nil)

type presentationRecord struct {
	ID                     string `gorm:"primaryKey"`
	ServiceID              string
	LamportTimestamp       int
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
	Credential   store.CredentialRecord `gorm:"foreignKey:CredentialID;references:ID"`
}

// TableName returns the table name for this DTO.
func (p credentialRecord) TableName() string {
	return "discovery_credential"
}

// presentationRefreshRecord is a tab-keeping record for clients to keep track of which DIDs should be registered on which Discovery Services.
type presentationRefreshRecord struct {
	// ServiceID refers to the entry record in discovery_service
	ServiceID string `gorm:"primaryKey"`
	// Did is Did that should be registered on the service.
	Did string `gorm:"primaryKey"`
	// NextRefresh is the Timestamp (seconds since Unix epoch) when the registration on the Discovery Service should be refreshed.
	NextRefresh int64
}

// TableName returns the table name for this DTO.
func (l presentationRefreshRecord) TableName() string {
	return "discovery_presentation_refresh"
}

type sqlStore struct {
	db *gorm.DB
}

func newSQLStore(db *gorm.DB, clientDefinitions map[string]ServiceDefinition) (*sqlStore, error) {
	// Creates entries in the discovery service table, if they don't exist yet
	for _, definition := range clientDefinitions {
		currentList := serviceRecord{
			ID: definition.ID,
		}
		if err := db.FirstOrCreate(&currentList, "id = ?", definition.ID).Error; err != nil {
			return nil, err
		}
	}
	return &sqlStore{db: db}, nil
}

// add adds a presentation to the list of presentations.
// If the given timestamp is 0, the server will assign a timestamp.
func (s *sqlStore) add(serviceID string, presentation vc.VerifiablePresentation, timestamp int) error {
	credentialSubjectID, err := credential.PresentationSigner(presentation)
	if err != nil {
		return err
	}
	if err := s.prune(); err != nil {
		return err
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		if timestamp == 0 {
			var newTs *int
			newTs, err = s.incrementTimestamp(tx, serviceID)
			if err != nil {
				return err
			}
			timestamp = *newTs
		} else {
			err = s.setTimestamp(tx, serviceID, timestamp)
			if err != nil {
				return err
			}
		}
		// Delete any previous presentations of the subject
		if err := tx.Delete(&presentationRecord{}, "service_id = ? AND credential_subject_id = ?", serviceID, credentialSubjectID.String()).
			Error; err != nil {
			return err
		}

		return storePresentation(tx, serviceID, timestamp, presentation)
	})
}

// storePresentation creates a presentationRecord from a VerifiablePresentation and stores it, with its credentials, in the database.
func storePresentation(tx *gorm.DB, serviceID string, timestamp int, presentation vc.VerifiablePresentation) error {
	credentialSubjectID, err := credential.PresentationSigner(presentation)
	if err != nil {
		return err
	}

	newPresentation := presentationRecord{
		ID:                     uuid.NewString(),
		ServiceID:              serviceID,
		CredentialSubjectID:    credentialSubjectID.String(),
		LamportTimestamp:       timestamp,
		PresentationID:         presentation.ID.String(),
		PresentationRaw:        presentation.Raw(),
		PresentationExpiration: presentation.JWT().Expiration().Unix(),
	}

	credentialStore := store.CredentialStore{}
	for _, verifiableCredential := range presentation.VerifiableCredential {
		cred, err := credentialStore.Store(tx, verifiableCredential)
		if err != nil {
			return err
		}
		newPresentation.Credentials = append(newPresentation.Credentials, credentialRecord{
			ID:             uuid.NewString(),
			PresentationID: newPresentation.ID,
			CredentialID:   cred.ID,
		})
	}

	return tx.Create(&newPresentation).Error
}

// get returns all presentations, registered on the given service, starting after the given timestamp.
// It also returns the latest timestamp of the returned presentations.
func (s *sqlStore) get(serviceID string, startAfter int) (map[string]vc.VerifiablePresentation, int, error) {
	var service serviceRecord
	if err := s.db.Find(&service, "id = ?", serviceID).Error; err != nil {
		return nil, 0, fmt.Errorf("query service '%s': %w", serviceID, err)
	}

	var rows []presentationRecord
	err := s.db.Order("lamport_timestamp ASC").Find(&rows, "service_id = ? AND lamport_timestamp > ?", serviceID, startAfter).Error
	if err != nil {
		return nil, 0, fmt.Errorf("query service '%s': %w", serviceID, err)
	}
	presentations := make(map[string]vc.VerifiablePresentation, len(rows))
	for _, row := range rows {
		presentation, err := vc.ParseVerifiablePresentation(row.PresentationRaw)
		if err != nil {
			return nil, 0, fmt.Errorf("parse presentation '%s' of service '%s': %w", row.PresentationID, serviceID, err)
		}
		presentations[fmt.Sprintf("%d", row.LamportTimestamp)] = *presentation
	}
	return presentations, service.LastLamportTimestamp, nil
}

// search searches for presentations, registered on the given service, matching the given query.
// The query is a map of JSON paths and expected string values, matched against the presentation's credentials.
// Wildcard matching is supported by prefixing or suffixing the value with an asterisk (*).
// It returns the presentations which contain credentials that match the given query.
func (s *sqlStore) search(serviceID string, query map[string]string) ([]vc.VerifiablePresentation, error) {
	stmt := s.db.Model(&presentationRecord{}).
		Where("service_id = ?", serviceID).
		Joins("inner join discovery_credential ON discovery_credential.presentation_id = discovery_presentation.id")
	stmt = store.CredentialStore{}.BuildSearchStatement(stmt, "discovery_credential.credential_id", query)

	var matches []presentationRecord
	if err := stmt.Preload("Credentials").Preload("Credentials.Credential").Find(&matches).Error; err != nil {
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

// incrementTimestamp increments the last_timestamp of the given service.
func (s *sqlStore) incrementTimestamp(tx *gorm.DB, serviceID string) (*int, error) {
	var service serviceRecord
	// Lock (SELECT FOR UPDATE) discovery_service row to prevent concurrent updates to the same list, which could mess up the last Timestamp.
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
		Where(serviceRecord{ID: serviceID}).
		Find(&service).
		Error; err != nil {
		return nil, err
	}
	service.ID = serviceID
	service.LastLamportTimestamp = service.LastLamportTimestamp + 1

	if err := tx.Save(service).Error; err != nil {
		return nil, err
	}
	return &service.LastLamportTimestamp, nil
}

// setTimestamp sets the last_timestamp of the given service.
func (s *sqlStore) setTimestamp(tx *gorm.DB, serviceID string, timestamp int) error {
	var service serviceRecord
	// Lock (SELECT FOR UPDATE) discovery_service row to prevent concurrent updates to the same list, which could mess up the last Timestamp.
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
		Where(serviceRecord{ID: serviceID}).
		Find(&service).
		Error; err != nil {
		return err
	}
	service.ID = serviceID
	service.LastLamportTimestamp = timestamp
	return tx.Save(service).Error
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

// updatePresentationRefreshTime creates/updates the next refresh time for a Verifiable Presentation on a Discovery Service.
// If nextRegistration is nil, the entry will be removed from the database.
func (s *sqlStore) updatePresentationRefreshTime(serviceID string, subjectDID did.DID, nextRefresh *time.Time) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		if nextRefresh == nil {
			// Delete registration
			return tx.Delete(&presentationRefreshRecord{}, "service_id = ? AND did = ?", serviceID, subjectDID.String()).Error
		}
		// Create or update it
		return tx.Save(presentationRefreshRecord{Did: subjectDID.String(), ServiceID: serviceID, NextRefresh: nextRefresh.Unix()}).Error
	})
}

func (s *sqlStore) getPresentationRefreshTime(serviceID string, subjectDID did.DID) (*time.Time, error) {
	var row presentationRefreshRecord
	if err := s.db.Find(&row, "service_id = ? AND did = ?", serviceID, subjectDID.String()).Error; err != nil {
		return nil, err
	}
	if row.NextRefresh == 0 {
		return nil, nil
	}
	result := time.Unix(row.NextRefresh, 0)
	return &result, nil
}

// getPresentationsToBeRefreshed returns all DID discovery service registrations that are due for refreshing.
// It returns a slice of service IDs and associated DIDs.
func (s *sqlStore) getPresentationsToBeRefreshed(now time.Time) ([]string, []did.DID, error) {
	var rows []presentationRefreshRecord
	if err := s.db.Find(&rows, "next_refresh < ?", now.Unix()).Error; err != nil {
		return nil, nil, err
	}
	var dids []did.DID
	var serviceIDs []string
	for _, row := range rows {
		parsedDID, err := did.ParseDID(row.Did)
		if err != nil {
			log.Logger().WithError(err).Errorf("Invalid DID in discovery presentation refresh table: %s", row.Did)
			continue
		}
		dids = append(dids, *parsedDID)
		serviceIDs = append(serviceIDs, row.ServiceID)
	}
	return serviceIDs, dids, nil
}

func (s *sqlStore) getTimestamp(serviceID string) (int, error) {
	var service serviceRecord
	err := s.db.Find(&service, "id = ?", serviceID).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return 0, nil
	} else if err != nil {
		return 0, fmt.Errorf("query service '%s': %w", serviceID, err)
	}
	return service.LastLamportTimestamp, nil
}
