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
	"gorm.io/gorm/schema"
)

var _ schema.Tabler = (*SqlVerificationMethod)(nil)

// SqlVerificationMethod is the gorm representation of the did_verificationmethod table
type SqlVerificationMethod struct {
	ID            string `gorm:"primaryKey"`
	DIDDocumentID string `gorm:"column:did_document_id"`
	KeyTypes      VerificationMethodKeyType
	Data          []byte
}

func (v SqlVerificationMethod) TableName() string {
	return "did_verificationmethod"
}

// VerificationMethodKeyType is used to marshal and unmarshal the key type to the DB
// The string representation in the DB is the base64 encoded bit mask
type VerificationMethodKeyType uint16
