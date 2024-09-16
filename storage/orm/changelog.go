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

package orm

import (
	"github.com/nuts-foundation/go-did/did"
	"gorm.io/gorm/schema"
)

const (
	DIDChangeCreated     = "created"
	DIDChangeUpdated     = "updated"
	DIDChangeDeactivated = "deactivated"
)

// DIDChangeLog represents a log of changes to a DID document
// It is used as a 2-phase commit log to keep did:nuts/did:web/others in sync.
type DIDChangeLog struct {
	DIDDocumentVersionID string `gorm:"primaryKey;column:did_document_version_id"`
	Type                 string
	TransactionID        string      `gorm:"column:transaction_id"`
	DIDDocumentVersion   DidDocument `gorm:"foreignKey:DIDDocumentVersionID;references:ID"`
}

func (d DIDChangeLog) TableName() string {
	return "did_change_log"
}

var _ schema.Tabler = (*DIDChangeLog)(nil)

// Method returns the DID method of the DID without the did: prefix
func (d DIDChangeLog) Method() string {
	id, err := did.ParseDID(d.DIDDocumentVersion.DID.ID)
	if err != nil {
		return "_unknown" // illegal method
	}
	return id.Method
}

// DID returns the did.DID of the DID Document
func (d DIDChangeLog) DID() did.DID {
	id, err := did.ParseDID(d.DIDDocumentVersion.DID.ID)
	if err != nil {
		return did.DID{}
	}
	return *id
}
