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
	"encoding/json"
	"errors"
	"github.com/nuts-foundation/nuts-node/storage/orm"
	"time"

	"github.com/google/uuid"
	"github.com/nuts-foundation/go-did/did"
	"gorm.io/gorm"
)

var _ DIDDocumentManager = (*SqlDIDDocumentManager)(nil)

// DIDDocumentManager is the interface to change data for the did_document table
type DIDDocumentManager interface {
	// CreateOrUpdate adds a new version of a DID document, starts at 1
	// If the DID does not exist yet, it will be created
	// It adds all verification methods, services, alsoKnownAs to the DID document
	// Not passing any verification methods will create an empty DID document, deactivation checking should be done by the caller
	CreateOrUpdate(did orm.DID, verificationMethods []orm.VerificationMethod, services []orm.SqlService) (*orm.DIDDocument, error)
	// Latest returns the latest version of a DID document
	// if notAfter is given, it will return the latest version before that time
	Latest(did did.DID, notAfter *time.Time) (*orm.DIDDocument, error)
}

// SqlDIDDocumentManager is the implementation of the DIDDocumentManager interface
type SqlDIDDocumentManager struct {
	tx *gorm.DB
}

// NewDIDDocumentManager creates a new DIDDocumentManager for an open transaction
func NewDIDDocumentManager(tx *gorm.DB) *SqlDIDDocumentManager {
	return &SqlDIDDocumentManager{tx: tx}
}

func (s *SqlDIDDocumentManager) CreateOrUpdate(did orm.DID, verificationMethods []orm.VerificationMethod, services []orm.SqlService) (*orm.DIDDocument, error) {
	latest := orm.DIDDocument{}
	err := s.tx.Preload("DID").Where("did = ?", did.ID).Order("version desc").First(&latest).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}
	version := latest.Version + 1
	id := uuid.New().String()
	// update DIDDocumentID for all VMs and services
	for i := range verificationMethods {
		verificationMethods[i].DIDDocumentID = id
	}
	for i := range services {
		services[i].DIDDocumentID = id
	}
	now := time.Now().Unix()
	doc := orm.DIDDocument{
		ID:                  id,
		DID:                 did,
		CreatedAt:           latest.CreatedAt,
		UpdatedAt:           now,
		Version:             version,
		VerificationMethods: verificationMethods,
		Services:            services,
	}
	// for future generations
	didDoc, _ := doc.GenerateDIDDocument()
	asJson, _ := json.Marshal(didDoc)
	doc.Raw = string(asJson)

	err = s.tx.Create(&doc).Error
	return &doc, err
}

func (s *SqlDIDDocumentManager) Latest(did did.DID, resolveTime *time.Time) (*orm.DIDDocument, error) {
	doc := orm.DIDDocument{}
	notAfter := time.Now().Add(time.Hour).Unix()
	if resolveTime != nil {
		notAfter = resolveTime.Unix()
	}
	err := s.tx.Preload("DID").Preload("DID.Aka").Preload("Services").Preload("VerificationMethods").Where("did = ? AND updated_at <= ?", did.String(), notAfter).Order("version desc").First(&doc).Error
	if err != nil {
		return nil, err
	}
	return &doc, err
}
