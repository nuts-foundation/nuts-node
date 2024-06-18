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
	"testing"

	"github.com/magiconair/properties/assert"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

var (
	alice = did.MustParseDID("did:web:example.com:iam:alice")
	bob   = did.MustParseDID("did:web:example.com:iam:bob")
)

func testDB(t *testing.T) *gorm.DB {
	//logrus.SetLevel(logrus.TraceLevel)
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())
	db := storageEngine.GetSQLDatabase()
	return db
}
func transaction(t *testing.T, db *gorm.DB) *gorm.DB {
	tx := db.Begin()
	t.Cleanup(func() {
		tx.Rollback()
	})
	return tx
}

func assertLen(t *testing.T, tx *gorm.DB, length int) {
	count := int64(0)
	err := tx.Table("did").Count(&count).Error
	require.NoError(t, err)
	assert.Equal(t, count, int64(length))
}
