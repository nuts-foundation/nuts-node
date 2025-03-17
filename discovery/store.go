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
	"database/sql/driver"
	"errors"
	"fmt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/json"
	"github.com/nuts-foundation/nuts-node/vcr/credential/store"
	"slices"
	"strconv"
	"strings"
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
	Seed                 string
	LastLamportTimestamp int
}

func (s serviceRecord) TableName() string {
	return "discovery_service"
}

var _ schema.Tabler = (*presentationRecord)(nil)

type SQLBool bool

type presentationRecord struct {
	ID                     string `gorm:"primaryKey"`
	ServiceID              string
	LamportTimestamp       int
	CredentialSubjectID    string
	PresentationID         string
	PresentationRaw        string
	PresentationExpiration int64
	Validated              SQLBool
	Credentials            []credentialRecord `gorm:"foreignKey:PresentationID;references:ID"`
}

func (s presentationRecord) TableName() string {
	return "discovery_presentation"
}

func (b *SQLBool) Scan(value interface{}) error {
	*b = false
	if value != nil {
		switch v := value.(type) {
		case int64:
			if v != 0 {
				*b = true
			}
		}
	}
	return nil
}

func (b SQLBool) Value() (driver.Value, error) {
	if b {
		return int64(1), nil
	}
	return int64(0), nil
}

func (b SQLBool) Bool() bool {
	return bool(b)
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
	// SubjectID is the ID of the subject that should be registered on the service.
	SubjectID string `gorm:"primaryKey"`
	// NextRefresh is the Timestamp (seconds since Unix epoch) when the registration on the Discovery Service should be refreshed.
	NextRefresh int
	// Parameters is a serialized JSON object containing parameters that should be used when registering the subject on the service.
	Parameters []byte
	// PresentationRefreshError is the error message that occurred during the refresh attempt.
	// It's loaded using a spearate query instead of using GORM's Preload, which fails on MS SQL Server if it spans multiple columns
	// See https://github.com/nuts-foundation/nuts-node/issues/3442
	PresentationRefreshError presentationRefreshError `gorm:"-"`
}

// TableName returns the table name for this DTO.
func (l presentationRefreshRecord) TableName() string {
	return "discovery_presentation_refresh"
}

// presentationRefreshError is a record of a failed refresh attempt.
type presentationRefreshError struct {
	// ServiceID refers to the entry record in discovery_service
	ServiceID string `gorm:"primaryKey"`
	// SubjectID is the ID of the subject that should be registered on the service.
	SubjectID string `gorm:"primaryKey"`
	// Error is the error message that occurred during the refresh attempt.
	Error string
	// LastOccurrence is the timestamp of the last occurrence of this error.
	LastOccurrence int
}

// TableName returns the table name for this DTO.
func (l presentationRefreshError) TableName() string {
	return "discovery_presentation_error"
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
func (s *sqlStore) add(serviceID string, presentation vc.VerifiablePresentation, seed string, timestamp int) (*presentationRecord, error) {
	credentialSubjectID, err := credential.PresentationSigner(presentation)
	if err != nil {
		return nil, err
	}
	if err := s.prune(); err != nil {
		return nil, err
	}
	var newPresentation *presentationRecord
	return newPresentation, s.db.Transaction(func(tx *gorm.DB) error {
		if timestamp == 0 {
			var newTs *int
			if len(seed) == 0 { // default for server
				seed = uuid.NewString()
			}
			newTs, err = s.incrementTimestamp(tx, serviceID, seed)
			if err != nil {
				return err
			}
			timestamp = *newTs
		} else {
			err = s.setTimestamp(tx, serviceID, seed, timestamp)
			if err != nil {
				return err
			}
		}
		// Delete any previous presentations of the subject
		if err := tx.Delete(&presentationRecord{}, "service_id = ? AND credential_subject_id = ?", serviceID, credentialSubjectID.String()).
			Error; err != nil {
			return err
		}

		newPresentation, err = storePresentation(tx, serviceID, timestamp, presentation)
		return err
	})
}

// storePresentation creates a presentationRecord from a VerifiablePresentation and stores it, with its credentials, in the database.
func storePresentation(tx *gorm.DB, serviceID string, timestamp int, presentation vc.VerifiablePresentation) (*presentationRecord, error) {
	credentialSubjectID, err := credential.PresentationSigner(presentation)
	if err != nil {
		return nil, err
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
			return nil, err
		}
		newPresentation.Credentials = append(newPresentation.Credentials, credentialRecord{
			ID:             uuid.NewString(),
			PresentationID: newPresentation.ID,
			CredentialID:   cred.ID,
		})
	}

	err = tx.Create(&newPresentation).Error
	return &newPresentation, err
}

// get returns all presentations, registered on the given service, starting after the given timestamp.
// It also returns the latest timestamp of the returned presentations.
func (s *sqlStore) get(serviceID string, startAfter int) (map[string]vc.VerifiablePresentation, string, int, error) {
	var service serviceRecord
	if err := s.db.Find(&service, "id = ?", serviceID).Error; err != nil {
		return nil, "", 0, fmt.Errorf("query service '%s': %w", serviceID, err)
	}

	var rows []presentationRecord
	err := s.db.Order("lamport_timestamp ASC").Find(&rows, "service_id = ? AND lamport_timestamp > ?", serviceID, startAfter).Error
	if err != nil {
		return nil, "", 0, fmt.Errorf("query service '%s': %w", serviceID, err)
	}
	presentations := make(map[string]vc.VerifiablePresentation, len(rows))
	for _, row := range rows {
		presentation, err := vc.ParseVerifiablePresentation(row.PresentationRaw)
		if err != nil {
			return nil, "", 0, fmt.Errorf("parse presentation '%s' of service '%s': %w", row.PresentationID, serviceID, err)
		}
		presentations[fmt.Sprintf("%d", row.LamportTimestamp)] = *presentation
	}
	return presentations, service.Seed, service.LastLamportTimestamp, nil
}

// search searches for presentations, registered on the given service, matching the given query.
// The query is a map of JSON paths and expected string values, matched against the presentation's credentials.
// Wildcard matching is supported by prefixing or suffixing the value with an asterisk (*).
// It returns the presentations which contain credentials that match the given query.
func (s *sqlStore) search(serviceID string, query map[string]string, allowUnvalidated bool) ([]vc.VerifiablePresentation, error) {
	// first only select columns also used in group by clause
	// if the query is empty, there's no need to do a join
	stmt := s.db.Model(&presentationRecord{}).Select("discovery_presentation.id").
		Where("service_id = ?", serviceID)
	if !allowUnvalidated {
		stmt = stmt.Where("validated != 0")
	}
	if len(query) > 0 {
		stmt = applyQuery(stmt, query)
	}
	stmt = stmt.Group("discovery_presentation.id")

	var matches []presentationRecord
	main := s.db.Preload("Credentials").Preload("Credentials.Credential").Model(&presentationRecord{}).Where("id in (?)", stmt)
	if err := main.Find(&matches).Error; err != nil {
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

// applyQuery is like vcr/credential/store/sql.go#BuildSearchStatement but for searching VPs a group by is needed which also requires a sub query
// at that point a generic search statement is not maintainable
func applyQuery(stmt *gorm.DB, query map[string]string) *gorm.DB {
	propertyColumns := map[string]string{
		"id":                   "credential.id",
		"issuer":               "credential.issuer",
		"type":                 "credential.type",
		"credentialSubject.id": "credential.subject_id",
	}

	stmt = stmt.Joins("inner join discovery_credential ON discovery_credential.presentation_id = discovery_presentation.id")
	stmt = stmt.Joins("inner join credential ON credential.id = discovery_credential.credential_id")
	numProps := 0
	for jsonPath, value := range query {
		// sort out wildcard mode: prefix and postfix asterisks (*) are replaced with %, which then is used in a LIKE query.
		// an asterisk is translated to IS NOT NULL
		// Otherwise, exact match (=) is used.
		var op = "= ?"
		if strings.TrimSpace(value) == "*" {
			op = "is not null"
			value = ""
		} else {
			if strings.HasPrefix(value, "*") {
				value = "%" + value[1:]
				op = "LIKE ?"
			}
			// and or
			if strings.HasSuffix(value, "*") {
				value = value[:len(value)-1] + "%"
				op = "LIKE ?"
			}
		}
		if column := propertyColumns[jsonPath]; column != "" {
			stmt = stmt.Where(column+" "+op, value)
		} else {
			// This property is not present as column, but indexed as key-value property.
			// Multiple (inner) joins to filter on a dynamic number of properties to filter on is not pretty, but it works
			alias := "p" + strconv.Itoa(numProps)
			numProps++
			// for an IS NOT NULL query, the value is ignored
			stmt = stmt.Joins("inner join credential_prop "+alias+" ON "+alias+".credential_id = credential.id AND "+alias+".path = ? AND "+alias+".value "+op, jsonPath, value)
		}
	}
	return stmt
}

// incrementTimestamp increments the last_timestamp of the given service. USed by server.
func (s *sqlStore) incrementTimestamp(tx *gorm.DB, serviceID string, seed string) (*int, error) {
	service, err := s.findAndLockService(tx, serviceID)
	if err != nil {
		return nil, err
	}
	service.ID = serviceID
	service.LastLamportTimestamp = service.LastLamportTimestamp + 1
	if len(service.Seed) == 0 { // first time this service is used, generate a new testSeed
		service.Seed = seed
	}

	if err := tx.Save(service).Error; err != nil {
		return nil, err
	}
	return &service.LastLamportTimestamp, nil
}

// setTimestamp sets the last_timestamp of the given service. Used by clients.
func (s *sqlStore) setTimestamp(tx *gorm.DB, serviceID string, seed string, timestamp int) error {
	service, err := s.findAndLockService(tx, serviceID)
	if err != nil {
		return err
	}
	service.ID = serviceID
	service.LastLamportTimestamp = timestamp
	service.Seed = seed
	return tx.Save(service).Error
}

// findAndLockService finds a service by ID and locks it, preventing concurrent updates to the same list.
// This is required for atomically processing updates from the Discovery Server.
func (s *sqlStore) findAndLockService(tx *gorm.DB, serviceID string) (serviceRecord, error) {
	var service serviceRecord
	// Lock (SELECT FOR UPDATE) discovery_service row to prevent concurrent updates to the same list, which could mess up the last Timestamp.
	// Microsoft SQL server does not support the locking clause, so we have to use a raw query instead.
	// See https://github.com/nuts-foundation/nuts-node/issues/3393
	if tx.Dialector.Name() == "sqlserver" {
		if err := tx.Raw("SELECT * FROM discovery_service WITH (UPDLOCK, ROWLOCK) WHERE id = ?", serviceID).Scan(&service).Error; err != nil {
			return serviceRecord{}, err
		}
	} else {
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where(serviceRecord{ID: serviceID}).
			Find(&service).
			Error; err != nil {
			return serviceRecord{}, err
		}
	}
	return service, nil
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

// allPresentations returns all presentations, the validated param can be used to select validated or unvalidated presentations
func (s *sqlStore) allPresentations(validated bool) ([]presentationRecord, error) {
	result := make([]presentationRecord, 0)
	stmt := s.db
	if validated {
		stmt = stmt.Where("validated != 0")
	} else {
		stmt = stmt.Where("validated = 0")
	}
	err := stmt.Find(&result).Error
	if err != nil {
		return nil, err
	}
	return result, nil
}

// updateValidated sets the validated flag for the given presentations
func (s *sqlStore) updateValidated(records []presentationRecord) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		for _, record := range records {
			if err := tx.Model(&presentationRecord{}).Where("id = ?", record.ID).Update("validated", SQLBool(true)).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// deletePresentationRecord removes a presentationRecord from the store based on its ID
func (s *sqlStore) deletePresentationRecord(id string) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		return tx.Delete(&presentationRecord{}, "id = ?", id).Error
	})
}

// updatePresentationRefreshTime creates/updates the next refresh time for a Verifiable Presentation on a Discovery Service.
// If nextRegistration is nil, the entry will be removed from the database.
func (s *sqlStore) updatePresentationRefreshTime(serviceID string, subjectID string, parameters map[string]interface{}, nextRefresh *time.Time) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		if nextRefresh == nil {
			// Delete registration
			return tx.Delete(&presentationRefreshRecord{}, "service_id = ? AND subject_id = ?", serviceID, subjectID).Error
		}
		// Create or update it
		var bytes []byte
		var err error
		if parameters != nil {
			bytes, err = json.Marshal(parameters)
			if err != nil {
				return err
			}
		}
		return tx.Save(presentationRefreshRecord{SubjectID: subjectID, ServiceID: serviceID, NextRefresh: int(nextRefresh.Unix()), Parameters: bytes}).Error
	})
}

func (s *sqlStore) getPresentationRefreshRecord(serviceID string, subjectID string) (*presentationRefreshRecord, error) {
	var row presentationRefreshRecord
	if err := s.db.Find(&row, "service_id = ? AND subject_id = ?", serviceID, subjectID).Error; err != nil {
		return nil, err
	}
	if row.NextRefresh == 0 {
		return nil, nil
	}
	// Load presentationRefreshError using a spearate query instead of using GORM's Preload, which fails on MS SQL Server if it spans multiple columns
	// See https://github.com/nuts-foundation/nuts-node/issues/3442
	if err := s.db.Find(&row.PresentationRefreshError, "service_id = ? AND subject_id = ?", serviceID, subjectID).Error; err != nil {
		return nil, err
	}
	return &row, nil
}

// getSubjectsToBeRefreshed returns all registered subject-service combinations that are due for refreshing.
func (s *sqlStore) getSubjectsToBeRefreshed(now time.Time) ([]refreshCandidate, error) {
	var candidates []presentationRefreshRecord
	if err := s.db.Model(&presentationRefreshRecord{}).Find(&candidates, "next_refresh < ?", now.Unix()).Error; err != nil {
		return nil, err
	}
	result := make([]refreshCandidate, len(candidates))
	for i, candidate := range candidates {
		c := refreshCandidate{
			ServiceID: candidate.ServiceID,
			SubjectID: candidate.SubjectID,
		}
		if len(candidate.Parameters) > 0 {
			if err := json.Unmarshal(candidate.Parameters, &c.Parameters); err != nil {
				return nil, err
			}
		}
		result[i] = c
	}
	return result, nil
}

func (s *sqlStore) setPresentationRefreshError(serviceID string, subjectID string, refreshErr error) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Delete(&presentationRefreshError{}, "service_id = ? AND subject_id = ?", serviceID, subjectID).Error; err != nil {
			return err
		}

		if refreshErr == nil {
			// a delete
			return nil
		}

		row := presentationRefreshError{
			ServiceID:      serviceID,
			SubjectID:      subjectID,
			Error:          refreshErr.Error(),
			LastOccurrence: int(time.Now().Unix()), //32bit supports stops at 03:14:07 on Tuesday, 19 January 2038
		}

		return tx.Save(&row).Error
	})
}

// refreshCandidate is a subset of presentationRefreshRecord
type refreshCandidate struct {
	// ServiceID is the presentationRefreshRecord.ServiceID
	ServiceID string
	// SubjectID is the presentationRefreshRecord.SubjectID
	SubjectID string
	// Parameters is the presentationRefreshRecord.Parameters
	Parameters map[string]interface{}
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

// getSubjectVPsOnService finds all VPs in the service that contain a credential issued to any of the subjectDIDs.
func (s *sqlStore) getSubjectVPsOnService(serviceID string, subjectDIDs []did.DID) (map[did.DID][]vc.VerifiablePresentation, error) {
	// this assumes Presentation Definitions for a service uses the subject wallet, meaning that a DID in a subject can
	// fulfill the PD using credentials issued to any of the subjectDIDs.
	// This complicates the search since we cannot filter on VP signer
	//
	// Example: a subject has 2 DIDs, did:web and did:nuts.
	// did:web has an organization credential
	// did:nuts has a use-case credential
	// The Presentation Definition of the use-case requires both credentials
	// The Discovery Service will contain VPs:
	// 	- VP with ID=123 that is signed by did:web and both credentials
	//  - VP with ID=abc that is signed by did:nuts and both credentials
	// since we can only filter on credential contents, a search on either DID will find both VPs.

	// get all VPs with a credential that has one of subjectDIDs as credentialSubject.id
	var vps []vc.VerifiablePresentation
	for _, subjectDID := range subjectDIDs {
		loopVPs, err := s.search(serviceID, map[string]string{
			"credentialSubject.id": subjectDID.String(),
		}, true)
		if err != nil {
			return nil, err
		}
		vps = append(vps, loopVPs...)
	}

	// deduplicate results by VP.ID and create a list of VPs per signer
	// TODO: confirm that there can only be one VP per discovery service-signer combination, meaning that results can be flattened.
	signerToVPs := map[did.DID][]vc.VerifiablePresentation{} // signerToVPs maps all VPs to their signer.
	var uniqueVPIDs []string                                 // keeps track of known VP.IDs
	for _, vp := range vps {
		vpID := vp.ID.String() // must be set according to Discovery Service RFC
		if slices.Contains(uniqueVPIDs, vpID) {
			// already in the map
			continue
		}

		signer, err := credential.PresentationSigner(vp)
		if err != nil {
			// this should not happen for VPs valid according to the Discovery Service RFC
			log.Logger().WithError(err).Warn("Could not determine signer of Verifiable Presentation")
			continue
		}

		// update loop vars at the same time
		uniqueVPIDs = append(uniqueVPIDs, vpID)
		signerToVPs[*signer] = append(signerToVPs[*signer], vp)
	}

	// filter signers not in subjectDIDs.
	// These can only exist when the subjectDIDs is incomplete, or VP signed by a different subject contains VCs issued to the current subject
	result := make(map[did.DID][]vc.VerifiablePresentation, len(subjectDIDs))
	for _, did := range subjectDIDs {
		result[did] = signerToVPs[did]
	}
	return result, nil
}

// wipeOnSeedChange wipes the store on a testSeed change.
func (s *sqlStore) wipeOnSeedChange(serviceID string, seed string) error {
	return s.db.Transaction(func(tx *gorm.DB) error {
		// get the service
		service, err := s.findAndLockService(tx, serviceID)
		if err != nil {
			return err
		}
		if service.Seed != seed && len(service.Seed) > 0 {
			log.Logger().
				WithField("serviceID", serviceID).
				Warnf("Seed changed, wiping store (old: %s, new: %s)", service.Seed, seed)

			// wipe the store
			if err = tx.Where("service_id = ?", serviceID).Delete(&presentationRecord{}).Error; err != nil {
				return err
			}

			// reset the testSeed and timestamp
			service.Seed = seed
			service.LastLamportTimestamp = 0
			return tx.Save(service).Error
		}
		return nil
	})
}
