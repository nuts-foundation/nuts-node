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

package discoveryservice

import (
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"testing"
)

func Test_sqlStore_exists(t *testing.T) {
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())

	t.Run("empty list", func(t *testing.T) {
		m := setupStore(t, storageEngine.GetSQLDatabase())
		exists, err := m.exists(testServiceID, aliceDID.String(), vpAlice.ID.String())
		assert.NoError(t, err)
		assert.False(t, exists)
	})
	t.Run("non-empty list, no match (other subject and ID)", func(t *testing.T) {
		m := setupStore(t, storageEngine.GetSQLDatabase())
		require.NoError(t, m.add(testServiceID, vpBob, nil))
		exists, err := m.exists(testServiceID, aliceDID.String(), vpAlice.ID.String())
		assert.NoError(t, err)
		assert.False(t, exists)
	})
	t.Run("non-empty list, no match (other list)", func(t *testing.T) {
		m := setupStore(t, storageEngine.GetSQLDatabase())
		require.NoError(t, m.add(testServiceID, vpAlice, nil))
		exists, err := m.exists("other", aliceDID.String(), vpAlice.ID.String())
		assert.NoError(t, err)
		assert.False(t, exists)
	})
	t.Run("non-empty list, match", func(t *testing.T) {
		m := setupStore(t, storageEngine.GetSQLDatabase())
		require.NoError(t, m.add(testServiceID, vpAlice, nil))
		exists, err := m.exists(testServiceID, aliceDID.String(), vpAlice.ID.String())
		assert.NoError(t, err)
		assert.True(t, exists)
	})
}

func setupStore(t *testing.T, db *gorm.DB) *sqlStore {
	resetStoreAfterTest(t, db)
	store, err := newSQLStore(db, testDefinitions())
	require.NoError(t, err)
	return store
}

func resetStoreAfterTest(t *testing.T, db *gorm.DB) {
	t.Cleanup(func() {
		underlyingDB, err := db.DB()
		require.NoError(t, err)
		_, err = underlyingDB.Exec("DELETE FROM discoveryservice_presentations")
		require.NoError(t, err)
		_, err = underlyingDB.Exec("DELETE FROM discoveryservices")
		require.NoError(t, err)
	})
}
