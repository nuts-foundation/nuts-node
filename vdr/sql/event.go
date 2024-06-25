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

package sql

import (
	"github.com/nuts-foundation/go-did/did"
	"gorm.io/gorm/schema"
)

type DIDEventLog struct {
	DIDDocumentVersionID string `gorm:"primaryKey;column:did_document_version_id"`
	EventType            string
	DIDDocumentVersion   DIDDocument `gorm:"foreignKey:DIDDocumentVersionID;references:ID"`
}

func (d DIDEventLog) TableName() string {
	return "did_event_log"
}

var _ schema.Tabler = (*DIDEventLog)(nil)

// Method returns the DID method of the DID without the did: prefix
func (d DIDEventLog) Method() string {
	id, _ := did.ParseDID(d.DIDDocumentVersion.DID.ID)
	return id.Method
}

func (d DIDEventLog) DID() did.DID {
	id, _ := did.ParseDID(d.DIDDocumentVersion.DID.ID)
	return *id
}
