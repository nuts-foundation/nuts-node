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

package didweb

import (
	"encoding/json"
	"errors"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/vdr/management"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

type store interface {
	delete(subjectDID did.DID) error
	create(subjectDID did.DID, methods ...did.VerificationMethod) error
	get(subjectDID did.DID) ([]did.VerificationMethod, []did.Service, error)
	list() ([]did.DID, error)
	createService(subjectDID did.DID, service did.Service) error
	updateService(subjectDID did.DID, id ssi.URI, service did.Service) error
	deleteService(subjectDID did.DID, id ssi.URI) error
}

var errServiceNotFound = errors.Join(management.ErrInvalidService, errors.New("not found"))
var errDuplicateService = errors.Join(management.ErrInvalidService, errors.New("service ID already exists"))
var errServiceDIDNotFound = errors.Join(management.ErrInvalidService, errors.New("unknown DID"))

var _ schema.Tabler = (*sqlDID)(nil)

type sqlDID struct {
	Did                 string                  `gorm:"primaryKey"`
	VerificationMethods []sqlVerificationMethod `gorm:"foreignKey:Did;references:Did"`
	Services            []sqlService            `gorm:"foreignKey:Did;references:Did"`
}

func (d sqlDID) TableName() string {
	return "did"
}

var _ schema.Tabler = (*sqlVerificationMethod)(nil)

type sqlVerificationMethod struct {
	ID   string `gorm:"primaryKey"`
	Did  string `gorm:"primaryKey"`
	Data []byte
}

func (v sqlVerificationMethod) TableName() string {
	return "did_verificationmethod"
}

var _ schema.Tabler = (*sqlService)(nil)

type sqlService struct {
	ID   string `gorm:"primaryKey"`
	Did  string `gorm:"primaryKey"`
	Data []byte
}

func (v sqlService) TableName() string {
	return "did_service"
}

var _ store = (*sqlStore)(nil)

type sqlStore struct {
	db *gorm.DB
}

func (s *sqlStore) create(did did.DID, methods ...did.VerificationMethod) error {
	record := &sqlDID{Did: did.String()}
	for _, method := range methods {
		data, _ := json.Marshal(method)
		record.VerificationMethods = append(record.VerificationMethods, sqlVerificationMethod{
			ID:   method.ID.String(),
			Did:  record.Did,
			Data: data,
		})
	}
	return s.db.Create(record).Error
}

func (s *sqlStore) get(id did.DID) ([]did.VerificationMethod, []did.Service, error) {
	var record sqlDID
	err := s.db.Model(&sqlDID{}).Where("did = ?", id.String()).
		Preload("VerificationMethods").
		Preload("Services").
		First(&record).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil, resolver.ErrNotFound
	}
	if err != nil {
		return nil, nil, err
	}

	var verificationMethods []did.VerificationMethod
	for _, curr := range record.VerificationMethods {
		var method did.VerificationMethod
		if err := json.Unmarshal(curr.Data, &method); err != nil {
			return nil, nil, err
		}
		verificationMethods = append(verificationMethods, method)
		vmID, err := did.ParseDIDURL(curr.ID)
		if err != nil {
			// weird
			return nil, nil, err
		}
		method.ID = *vmID
	}

	var services []did.Service
	for _, curr := range record.Services {
		var service did.Service
		if err := json.Unmarshal(curr.Data, &service); err != nil {
			return nil, nil, err
		}
		services = append(services, service)
	}

	return verificationMethods, services, nil
}

func (s *sqlStore) delete(subjectDID did.DID) error {
	result := s.db.Model(&sqlDID{}).Where("did = ?", subjectDID.String()).Delete(&sqlDID{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return resolver.ErrNotFound
	}
	return nil
}

// list returns all DIDs in the store.
func (s *sqlStore) list() ([]did.DID, error) {
	var list []sqlDID
	err := s.db.Model(&sqlDID{}).Select("did").Find(&list).Error
	if err != nil {
		return nil, err
	}
	var result []did.DID
	for _, curr := range list {
		parsed, err := did.ParseDID(curr.Did)
		if err != nil {
			return nil, err
		}
		result = append(result, *parsed)
	}
	return result, nil
}

// createService creates a new service in the DID document identified by subjectDID.
// It does not validate the service.
func (s *sqlStore) createService(subjectDID did.DID, service did.Service) error {
	data, _ := json.Marshal(service)
	record := &sqlService{
		ID:   service.ID.String(),
		Did:  subjectDID.String(),
		Data: data,
	}
	err := s.db.Create(record).Error
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return errDuplicateService
	}
	if errors.Is(err, gorm.ErrForeignKeyViolated) {
		return errServiceDIDNotFound
	}
	return err
}

func (s *sqlStore) updateService(subjectDID did.DID, id ssi.URI, service did.Service) error {
	data, _ := json.Marshal(service)
	record := &sqlService{
		ID:   service.ID.String(),
		Did:  subjectDID.String(),
		Data: data,
	}
	result := s.db.Model(&sqlService{}).Where("did = ? AND id = ?", subjectDID.String(), id.String()).Updates(record)
	err := result.Error
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return errDuplicateService
	}
	if result.RowsAffected == 0 {
		return errServiceNotFound
	}
	return nil
}

func (s *sqlStore) deleteService(subjectDID did.DID, id ssi.URI) error {
	result := s.db.Model(&sqlService{}).Where("did = ? AND id = ?", subjectDID.String(), id.String()).Delete(&sqlService{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return errServiceNotFound
	}
	return nil
}
