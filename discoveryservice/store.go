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
	credential2 "github.com/nuts-foundation/nuts-node/vcr/credential"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/schema"
	"time"
)

var ErrServiceNotFound = errors.New("discovery service not found")
var ErrPresentationAlreadyExists = errors.New("presentation already exists")

type discoveryService struct {
	ID        string `gorm:"primaryKey"`
	Timestamp uint64
}

func (s discoveryService) TableName() string {
	return "discoveryservices"
}

var _ schema.Tabler = (*servicePresentation)(nil)

type servicePresentation struct {
	ID                     string `gorm:"primaryKey"`
	ServiceID              string
	Timestamp              uint64
	CredentialSubjectID    string
	PresentationID         string
	PresentationRaw        string
	PresentationExpiration int64
	Credentials            []credential `gorm:"foreignKey:PresentationID;references:ID"`
}

func (s servicePresentation) TableName() string {
	return "discoveryservice_presentations"
}

// credential is a Verifiable Credential, part of a presentation (entry) on a use case list.
type credential struct {
	// ID is the unique identifier of the entry.
	ID string `gorm:"primaryKey"`
	// PresentationID corresponds to the discoveryservice_presentations record ID (not VerifiablePresentation.ID) this credential belongs to.
	PresentationID string
	// CredentialID contains the 'id' property of the Verifiable Credential.
	CredentialID string
	// CredentialIssuer contains the 'issuer' property of the Verifiable Credential.
	CredentialIssuer string
	// CredentialSubjectID contains the 'credentialSubject.id' property of the Verifiable Credential.
	CredentialSubjectID string
	// CredentialType contains the 'type' property of the Verifiable Credential (not being 'VerifiableCredential').
	CredentialType *string
	Properties     []credentialProperty `gorm:"foreignKey:ID;references:ID"`
}

// TableName returns the table name for this DTO.
func (p credential) TableName() string {
	return "discoveryservice_credentials"
}

// credentialProperty is a property of a Verifiable Credential in a Verifiable Presentation in a discovery service.
type credentialProperty struct {
	// ID refers to the entry record in discoveryservice_credentials
	ID string `gorm:"primaryKey"`
	// Key is JSON path of the property.
	Key string `gorm:"primaryKey"`
	// Value is the value of the property.
	Value string
}

// TableName returns the table name for this DTO.
func (l credentialProperty) TableName() string {
	return "discoveryservice_credential_props"
}

type sqlStore struct {
	db *gorm.DB
}

func newSQLStore(db *gorm.DB, definitions map[string]Definition) (*sqlStore, error) {
	// Creates entries in the discovery service table with initial timestamp, if they don't exist yet
	for _, definition := range definitions {
		currentList := discoveryService{
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
	credentialSubjectID, err := credential2.PresentationSigner(presentation)
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
		timestamp, err := s.updateTimestamp(tx, serviceID, timestamp)
		if err != nil {
			return err
		}
		// Delete any previous presentations of the subject
		if err := tx.Delete(&servicePresentation{}, "service_id = ? AND credential_subject_id = ?", serviceID, credentialSubjectID.String()).
			Error; err != nil {
			return err
		}
		// Now store the presentation itself
		return tx.Create(&servicePresentation{
			ID:                     uuid.NewString(),
			ServiceID:              serviceID,
			Timestamp:              uint64(timestamp),
			CredentialSubjectID:    credentialSubjectID.String(),
			PresentationID:         presentation.ID.String(),
			PresentationRaw:        presentation.Raw(),
			PresentationExpiration: presentation.JWT().Expiration().Unix(),
		}).Error
	})
}

func (s *sqlStore) get(serviceID string, startAt Timestamp) ([]vc.VerifiablePresentation, *Timestamp, error) {
	var rows []servicePresentation
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

func (s *sqlStore) updateTimestamp(tx *gorm.DB, serviceID string, newTimestamp *Timestamp) (Timestamp, error) {
	var result discoveryService
	// Lock (SELECT FOR UPDATE) discoveryservices row to prevent concurrent updates to the same list, which could mess up the lamport timestamp.
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
		Where(discoveryService{ID: serviceID}).
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
	if err := s.db.Model(servicePresentation{}).Where(servicePresentation{
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
	result := s.db.Where("presentation_expiration < ?", time.Now().Unix()).Delete(servicePresentation{})
	if result.Error != nil {
		return 0, fmt.Errorf("prune presentations: %w", result.Error)
	}
	return int(result.RowsAffected), nil
}
