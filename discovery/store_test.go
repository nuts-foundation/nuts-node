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

package discovery

import (
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"sync"
	"testing"
	"time"
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
		require.NoError(t, m.add(testServiceID, vpBob, 0))
		exists, err := m.exists(testServiceID, aliceDID.String(), vpAlice.ID.String())
		assert.NoError(t, err)
		assert.False(t, exists)
	})
	t.Run("non-empty list, no match (other list)", func(t *testing.T) {
		m := setupStore(t, storageEngine.GetSQLDatabase())
		require.NoError(t, m.add(testServiceID, vpAlice, 0))
		exists, err := m.exists("other", aliceDID.String(), vpAlice.ID.String())
		assert.NoError(t, err)
		assert.False(t, exists)
	})
	t.Run("non-empty list, match", func(t *testing.T) {
		m := setupStore(t, storageEngine.GetSQLDatabase())
		require.NoError(t, m.add(testServiceID, vpAlice, 0))
		exists, err := m.exists(testServiceID, aliceDID.String(), vpAlice.ID.String())
		assert.NoError(t, err)
		assert.True(t, exists)
	})
}

func Test_sqlStore_add(t *testing.T) {
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())

	t.Run("no credentials in presentation", func(t *testing.T) {
		m := setupStore(t, storageEngine.GetSQLDatabase())
		err := m.add(testServiceID, createPresentation(aliceDID), 0)
		assert.NoError(t, err)
	})

	t.Run("passing timestamp updates last_timestamp", func(t *testing.T) {
		m := setupStore(t, storageEngine.GetSQLDatabase())
		err := m.add(testServiceID, createPresentation(aliceDID), 1)
		require.NoError(t, err)

		timestamp, err := m.getTimestamp(testServiceID)

		require.NoError(t, err)
		assert.Equal(t, 1, timestamp)
	})

	t.Run("replaces previous presentation of same subject", func(t *testing.T) {
		m := setupStore(t, storageEngine.GetSQLDatabase())

		secondVP := createPresentation(aliceDID, vcAlice)
		require.NoError(t, m.add(testServiceID, vpAlice, 0))
		require.NoError(t, m.add(testServiceID, secondVP, 0))

		// First VP should not exist
		exists, err := m.exists(testServiceID, aliceDID.String(), vpAlice.ID.String())
		require.NoError(t, err)
		assert.False(t, exists)

		// Only second VP should exist
		exists, err = m.exists(testServiceID, aliceDID.String(), secondVP.ID.String())
		require.NoError(t, err)
		assert.True(t, exists)
	})
}

func Test_sqlStore_get(t *testing.T) {
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())

	t.Run("empty list, 0 timestamp", func(t *testing.T) {
		m := setupStore(t, storageEngine.GetSQLDatabase())
		presentations, timestamp, err := m.get(testServiceID, 0)
		assert.NoError(t, err)
		assert.Empty(t, presentations)
		assert.Equal(t, 0, timestamp)
	})
	t.Run("1 entry, 0 timestamp", func(t *testing.T) {
		m := setupStore(t, storageEngine.GetSQLDatabase())
		require.NoError(t, m.add(testServiceID, vpAlice, 0))
		presentations, timestamp, err := m.get(testServiceID, 0)
		assert.NoError(t, err)
		assert.Equal(t, map[string]vc.VerifiablePresentation{"1": vpAlice}, presentations)
		assert.Equal(t, 1, timestamp)
	})
	t.Run("2 entries, 0 timestamp", func(t *testing.T) {
		m := setupStore(t, storageEngine.GetSQLDatabase())
		require.NoError(t, m.add(testServiceID, vpAlice, 0))
		require.NoError(t, m.add(testServiceID, vpBob, 0))
		presentations, timestamp, err := m.get(testServiceID, 0)
		assert.NoError(t, err)
		assert.Equal(t, map[string]vc.VerifiablePresentation{"1": vpAlice, "2": vpBob}, presentations)
		assert.Equal(t, 2, timestamp)
	})
	t.Run("2 entries, start after first", func(t *testing.T) {
		m := setupStore(t, storageEngine.GetSQLDatabase())
		require.NoError(t, m.add(testServiceID, vpAlice, 0))
		require.NoError(t, m.add(testServiceID, vpBob, 0))
		presentations, timestamp, err := m.get(testServiceID, 1)
		assert.NoError(t, err)
		assert.Equal(t, map[string]vc.VerifiablePresentation{"2": vpBob}, presentations)
		assert.Equal(t, 2, timestamp)
	})
	t.Run("2 entries, start at end", func(t *testing.T) {
		m := setupStore(t, storageEngine.GetSQLDatabase())
		require.NoError(t, m.add(testServiceID, vpAlice, 0))
		require.NoError(t, m.add(testServiceID, vpBob, 0))
		presentations, timestamp, err := m.get(testServiceID, 2)
		assert.NoError(t, err)
		assert.Equal(t, map[string]vc.VerifiablePresentation{}, presentations)
		assert.Equal(t, 2, timestamp)
	})
	t.Run("concurrency", func(t *testing.T) {
		c := setupStore(t, storageEngine.GetSQLDatabase())
		wg := &sync.WaitGroup{}
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				err := c.add(testServiceID, createPresentation(aliceDID, vcAlice), 0)
				require.NoError(t, err)
			}()
		}
		wg.Wait()
	})
}

func Test_sqlStore_search(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())
	t.Cleanup(func() {
		_ = storageEngine.Shutdown()
	})

	t.Run("empty database", func(t *testing.T) {
		c := setupStore(t, storageEngine.GetSQLDatabase())
		actualVPs, err := c.search(testServiceID, map[string]string{})
		require.NoError(t, err)
		require.Len(t, actualVPs, 0)
	})
	t.Run("found", func(t *testing.T) {
		vps := []vc.VerifiablePresentation{vpAlice}
		c := setupStore(t, storageEngine.GetSQLDatabase())
		for _, vp := range vps {
			err := c.add(testServiceID, vp, 0)
			require.NoError(t, err)
		}

		actualVPs, err := c.search(testServiceID, map[string]string{
			"credentialSubject.person.givenName": "Alice",
		})
		require.NoError(t, err)
		require.Len(t, actualVPs, 1)
		assert.Equal(t, vpAlice.ID.String(), actualVPs[0].ID.String())
	})
	t.Run("not found", func(t *testing.T) {
		vps := []vc.VerifiablePresentation{vpAlice, vpBob}
		c := setupStore(t, storageEngine.GetSQLDatabase())
		for _, vp := range vps {
			err := c.add(testServiceID, vp, 0)
			require.NoError(t, err)
		}
		actualVPs, err := c.search(testServiceID, map[string]string{
			"credentialSubject.person.givenName": "Charlie",
		})
		require.NoError(t, err)
		require.Len(t, actualVPs, 0)
	})
}

func Test_sqlStore_getStaleDIDRegistrations(t *testing.T) {
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())
	t.Cleanup(func() {
		_ = storageEngine.Shutdown()
	})

	now := time.Now()
	t.Run("empty list", func(t *testing.T) {
		c := setupStore(t, storageEngine.GetSQLDatabase())
		serviceIDs, dids, err := c.getPresentationsToBeRefreshed(now)
		require.NoError(t, err)
		assert.Empty(t, serviceIDs)
		assert.Empty(t, dids)
	})
	t.Run("1 entry, not stale", func(t *testing.T) {
		c := setupStore(t, storageEngine.GetSQLDatabase())
		require.NoError(t, c.updatePresentationRefreshTime(testServiceID, aliceDID, &now))
		serviceIDs, dids, err := c.getPresentationsToBeRefreshed(time.Now().Add(-1 * time.Hour))
		require.NoError(t, err)
		assert.Empty(t, serviceIDs)
		assert.Empty(t, dids)
	})
	t.Run("1 entry, stale", func(t *testing.T) {
		c := setupStore(t, storageEngine.GetSQLDatabase())
		require.NoError(t, c.updatePresentationRefreshTime(testServiceID, aliceDID, &now))
		serviceIDs, dids, err := c.getPresentationsToBeRefreshed(time.Now().Add(time.Hour))
		require.NoError(t, err)
		assert.Equal(t, []string{testServiceID}, serviceIDs)
		assert.Equal(t, []did.DID{aliceDID}, dids)
	})
	t.Run("does not return removed entry", func(t *testing.T) {
		c := setupStore(t, storageEngine.GetSQLDatabase())
		require.NoError(t, c.updatePresentationRefreshTime(testServiceID, aliceDID, &now))

		// Assert it's there
		serviceIDs, dids, err := c.getPresentationsToBeRefreshed(time.Now().Add(time.Hour))
		require.NoError(t, err)
		assert.Equal(t, []string{testServiceID}, serviceIDs)
		assert.Equal(t, []did.DID{aliceDID}, dids)

		// Remove it
		require.NoError(t, c.updatePresentationRefreshTime(testServiceID, aliceDID, nil))
		serviceIDs, dids, err = c.getPresentationsToBeRefreshed(time.Now().Add(time.Hour))
		require.NoError(t, err)
		assert.Empty(t, serviceIDs)
		assert.Empty(t, dids)
	})
}

func Test_sqlStore_getPresentationRefreshTime(t *testing.T) {
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())

	t.Run("no entry", func(t *testing.T) {
		c := setupStore(t, storageEngine.GetSQLDatabase())
		ts, err := c.getPresentationRefreshTime(testServiceID, aliceDID)
		require.NoError(t, err)
		assert.Nil(t, ts)
	})
	t.Run("entry exists", func(t *testing.T) {
		c := setupStore(t, storageEngine.GetSQLDatabase())
		now := time.Now().Truncate(time.Second)
		require.NoError(t, c.updatePresentationRefreshTime(testServiceID, aliceDID, &now))
		ts, err := c.getPresentationRefreshTime(testServiceID, aliceDID)
		require.NoError(t, err)
		assert.Equal(t, now, *ts)
	})
}

func setupStore(t *testing.T, db *gorm.DB) *sqlStore {
	resetStore(t, db)
	defs := testDefinitions()
	store, err := newSQLStore(db, defs)
	require.NoError(t, err)
	return store
}

func resetStore(t *testing.T, db *gorm.DB) {
	// related tables are emptied due to on-delete-cascade clause
	tableNames := []string{"discovery_service", "discovery_presentation", "discovery_credential", "credential", "credential_prop"}
	for _, tableName := range tableNames {
		require.NoError(t, db.Exec("DELETE FROM "+tableName).Error)
	}
}
