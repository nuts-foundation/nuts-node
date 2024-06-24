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
	"database/sql/driver"
	"encoding/base64"
	"errors"
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
type VerificationMethodKeyType uint8

// Scan decodes string value to byte slice
func (kt *VerificationMethodKeyType) Scan(value interface{}) error {
	var err error
	if value == nil {
		return nil
	}
	switch v := value.(type) {
	case string:
		*kt, err = stringToUint(v)
	default:
		err = errors.New("not supported")
	}
	return err
}

// Value returns base64 encoded value
func (kt VerificationMethodKeyType) Value() (driver.Value, error) {
	return uintToString(kt)
}

// stringToUint decodes a base64 encoded string to a uint
func stringToUint(s string) (VerificationMethodKeyType, error) {
	if s == "" {
		return 0, nil
	}
	bytes, err := base64.RawStdEncoding.DecodeString(s)
	if err != nil {
		return 0, err
	}
	if len(bytes) > 1 {
		return 0, errors.New("keyTypes is too long")
	}
	return VerificationMethodKeyType(bytes[0]), nil
}

// uintToString encodes a uint to a base64 encoded string
func uintToString(u VerificationMethodKeyType) (string, error) {
	if u == 0 {
		return "", nil
	}
	// convert uint to bytes array
	bytes := [1]byte{byte(u)}
	return base64.RawStdEncoding.EncodeToString(bytes[:]), nil
}
