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
	"gorm.io/gorm/schema"
)

var _ schema.Tabler = (*VerificationMethod)(nil)

// VerificationMethod is the gorm representation of the did_verificationmethod table
type VerificationMethod struct {
	ID            string `gorm:"primaryKey"`
	DIDDocumentID string `gorm:"column:did_document_id"`
	KeyTypes      VerificationMethodKeyType
	Weight        int16
	Data          []byte
}

func (v VerificationMethod) TableName() string {
	return "did_verificationmethod"
}

// VerificationMethodKeyType is used to marshal and unmarshal the key type to the DB
// SQL databases use SMALLINT for this type
type VerificationMethodKeyType int16
