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

package didsubject

import (
	"errors"
	"github.com/nuts-foundation/nuts-node/storage/orm"

	"github.com/nuts-foundation/go-did/did"
	"gorm.io/gorm"
)

var _ DIDManager = (*SqlDIDManager)(nil)

// DIDManager is the interface to change data for the did table
type DIDManager interface {
	// Add adds a new DID to the database, this is also done via DIDDocumentManager.CreateOrUpdate
	Add(subject string, did did.DID) (*orm.DID, error)
	// All returns all DIDs in the database
	All() ([]orm.DID, error)
	// Delete removes a DID from the database
	Delete(did did.DID) error
	// DeleteAll removes all DIDs for a subject from the database
	DeleteAll(subject string) error
	// Find returns a DID by its ID
	Find(id did.DID) (*orm.DID, error)
	// FindBySubject returns all DIDs for a subject
	FindBySubject(subject string) ([]orm.DID, error)
}

// SqlDIDManager is the implementation of the DIDManager interface
type SqlDIDManager struct {
	tx *gorm.DB
}

// NewDIDManager creates a new DIDManager for an open transaction
func NewDIDManager(tx *gorm.DB) *SqlDIDManager {
	return &SqlDIDManager{tx: tx}
}

func (s SqlDIDManager) Add(subject string, did did.DID) (*orm.DID, error) {
	added := orm.DID{ID: did.String(), Subject: subject}
	return &added, s.tx.Create(&added).Error
}

func (s SqlDIDManager) All() ([]orm.DID, error) {
	dids := make([]orm.DID, 0)
	return dids, s.tx.Find(&dids).Error
}

func (s SqlDIDManager) Delete(did did.DID) error {
	return s.tx.Where("id = ?", did.String()).Delete(&orm.DID{}).Error
}

func (s SqlDIDManager) DeleteAll(subject string) error {
	return s.tx.Where("subject = ?", subject).Delete(&orm.DID{}).Error
}

func (s SqlDIDManager) Find(id did.DID) (*orm.DID, error) {
	var did orm.DID
	err := s.tx.First(&did, "id = ?", id.String()).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &did, nil
}

func (s SqlDIDManager) FindBySubject(subject string) ([]orm.DID, error) {
	dids := make([]orm.DID, 0)
	err := s.tx.Find(&dids, "subject = ?", subject).Error
	if err != nil {
		return nil, err
	}
	if len(dids) == 0 {
		return nil, ErrSubjectNotFound
	}
	return dids, nil
}

func (s SqlDIDManager) SubjectExists(subject string) (bool, error) {
	var count int64
	err := s.tx.Model(&orm.DID{}).Where("subject = ?", subject).Count(&count).Error
	return count > 0, err
}
