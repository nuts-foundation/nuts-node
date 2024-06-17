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

	"github.com/nuts-foundation/go-did/did"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

// DID is the gorm representation of the DID table
type DID struct {
	ID      string `gorm:"primaryKey"`
	Subject string `gorm:"column:subject"`
	Aka     []DID  `gorm:"foreignKey:Subject;references:Subject"`
}

func (d DID) TableName() string {
	return "did"
}

var _ DIDManager = (*SqlDIDManager)(nil)
var _ schema.Tabler = (*DID)(nil)

// DIDManager is the interface to change data for the did table
type DIDManager interface {
	// Add adds a new DID to the database, this is also done via DIDDocumentManager.CreateOrUpdate
	Add(subject string, did did.DID) (*DID, error)
	// All returns all DIDs in the database
	All() ([]DID, error)
	// Delete removes a DID from the database
	Delete(did did.DID) error
	// DeleteAll removes all DIDs for a subject from the database
	DeleteAll(subject string) error
	// Find returns a DID by its ID
	Find(id did.DID) (*DID, error)
	// FindBySubject returns all DIDs for a subject
	FindBySubject(subject string) ([]DID, error)
}

// SqlDIDManager is the implementation of the DIDManager interface
type SqlDIDManager struct {
	tx *gorm.DB
}

// NewDIDManager creates a new DIDManager for an open transaction
func NewDIDManager(tx *gorm.DB) *SqlDIDManager {
	return &SqlDIDManager{tx: tx}
}

func (s SqlDIDManager) Add(subject string, did did.DID) (*DID, error) {
	added := DID{ID: did.String(), Subject: subject}
	err := s.tx.Create(&added).Error
	if err != nil {
		return nil, err
	}
	return &added, nil
}

func (s SqlDIDManager) All() ([]DID, error) {
	dids := make([]DID, 0)
	err := s.tx.Preload("Aka").Find(&dids).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return dids, nil
	}
	return dids, err
}

func (s SqlDIDManager) Delete(did did.DID) error {
	return s.tx.Where("id = ?", did.String()).Delete(&DID{}).Error
}

func (s SqlDIDManager) DeleteAll(subject string) error {
	return s.tx.Where("subject = ?", subject).Delete(&DID{}).Error
}

func (d SqlDIDManager) Find(id did.DID) (*DID, error) {
	var did DID
	err := d.tx.Preload("Aka").First(&did, "id = ?", id.String()).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &did, nil
}

func (d SqlDIDManager) FindBySubject(subject string) ([]DID, error) {
	dids := make([]DID, 0)
	err := d.tx.Preload("Aka").Find(&dids, "subject = ?", subject).Error
	return dids, err
}
