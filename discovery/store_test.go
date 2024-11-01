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
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/core/to"
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
		_, err := m.add(testServiceID, vpBob, testSeed, 0)
		require.NoError(t, err)
		exists, err := m.exists(testServiceID, aliceDID.String(), vpAlice.ID.String())
		assert.NoError(t, err)
		assert.False(t, exists)
	})
	t.Run("non-empty list, no match (other list)", func(t *testing.T) {
		m := setupStore(t, storageEngine.GetSQLDatabase())
		_, err := m.add(testServiceID, vpAlice, testSeed, 0)
		require.NoError(t, err)
		exists, err := m.exists("other", aliceDID.String(), vpAlice.ID.String())
		assert.NoError(t, err)
		assert.False(t, exists)
	})
	t.Run("non-empty list, match", func(t *testing.T) {
		m := setupStore(t, storageEngine.GetSQLDatabase())
		_, err := m.add(testServiceID, vpAlice, testSeed, 0)
		require.NoError(t, err)
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
		_, err := m.add(testServiceID, createPresentation(aliceDID), testSeed, 0)
		assert.NoError(t, err)
	})

	t.Run("seed", func(t *testing.T) {
		t.Run("passing seed updates last_seed", func(t *testing.T) {
			m := setupStore(t, storageEngine.GetSQLDatabase())
			_, err := m.add(testServiceID, createPresentation(aliceDID), testSeed, 0)
			require.NoError(t, err)

			_, seed, _, err := m.get(testServiceID, 0)

			require.NoError(t, err)
			assert.Equal(t, testSeed, seed)
		})
		t.Run("generated seed", func(t *testing.T) {
			m := setupStore(t, storageEngine.GetSQLDatabase())
			_, err := m.add(testServiceID, createPresentation(aliceDID), "", 0)
			require.NoError(t, err)

			_, seed, _, err := m.get(testServiceID, 0)

			require.NoError(t, err)
			assert.Len(t, seed, 36) // uuid v4
		})
	})

	t.Run("passing timestamp updates last_timestamp", func(t *testing.T) {
		m := setupStore(t, storageEngine.GetSQLDatabase())
		_, err := m.add(testServiceID, createPresentation(aliceDID), testSeed, 1)
		require.NoError(t, err)

		timestamp, err := m.getTimestamp(testServiceID)

		require.NoError(t, err)
		assert.Equal(t, 1, timestamp)
	})

	t.Run("replaces previous presentation of same subject", func(t *testing.T) {
		m := setupStore(t, storageEngine.GetSQLDatabase())

		secondVP := createPresentation(aliceDID, vcAlice)
		_, err := m.add(testServiceID, vpAlice, testSeed, 0)
		require.NoError(t, err)
		_, err = m.add(testServiceID, secondVP, testSeed, 0)
		require.NoError(t, err)

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
		presentations, seed, timestamp, err := m.get(testServiceID, 0)
		assert.NoError(t, err)
		assert.Empty(t, presentations)
		assert.Equal(t, 0, timestamp)
		assert.Empty(t, seed)
	})
	t.Run("1 entry, 0 timestamp", func(t *testing.T) {
		m := setupStore(t, storageEngine.GetSQLDatabase())
		_, err := m.add(testServiceID, vpAlice, testSeed, 0)
		require.NoError(t, err)
		presentations, seed, timestamp, err := m.get(testServiceID, 0)
		assert.NoError(t, err)
		assert.Equal(t, map[string]vc.VerifiablePresentation{"1": vpAlice}, presentations)
		assert.Equal(t, 1, timestamp)
		assert.Equal(t, testSeed, seed)
	})
	t.Run("2 entries, 0 timestamp", func(t *testing.T) {
		m := setupStore(t, storageEngine.GetSQLDatabase())
		_, err := m.add(testServiceID, vpAlice, testSeed, 0)
		require.NoError(t, err)
		_, err = m.add(testServiceID, vpBob, testSeed, 0)
		require.NoError(t, err)
		presentations, _, timestamp, err := m.get(testServiceID, 0)
		assert.NoError(t, err)
		assert.Equal(t, map[string]vc.VerifiablePresentation{"1": vpAlice, "2": vpBob}, presentations)
		assert.Equal(t, 2, timestamp)
	})
	t.Run("2 entries, start after first", func(t *testing.T) {
		m := setupStore(t, storageEngine.GetSQLDatabase())
		_, err := m.add(testServiceID, vpAlice, testSeed, 0)
		require.NoError(t, err)
		_, err = m.add(testServiceID, vpBob, testSeed, 0)
		require.NoError(t, err)
		presentations, _, timestamp, err := m.get(testServiceID, 1)
		assert.NoError(t, err)
		assert.Equal(t, map[string]vc.VerifiablePresentation{"2": vpBob}, presentations)
		assert.Equal(t, 2, timestamp)
	})
	t.Run("2 entries, start at end", func(t *testing.T) {
		m := setupStore(t, storageEngine.GetSQLDatabase())
		_, err := m.add(testServiceID, vpAlice, testSeed, 0)
		require.NoError(t, err)
		_, err = m.add(testServiceID, vpBob, testSeed, 0)
		presentations, _, timestamp, err := m.get(testServiceID, 2)
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
				_, err := c.add(testServiceID, createPresentation(aliceDID, vcAlice), testSeed, 0)
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
		actualVPs, err := c.search(testServiceID, map[string]string{}, true)
		require.NoError(t, err)
		require.Len(t, actualVPs, 0)
	})
	t.Run("found", func(t *testing.T) {
		vps := []vc.VerifiablePresentation{vpAlice}
		c := setupStore(t, storageEngine.GetSQLDatabase())
		for _, vp := range vps {
			_, err := c.add(testServiceID, vp, testSeed, 0)
			require.NoError(t, err)
		}

		actualVPs, err := c.search(testServiceID, map[string]string{
			"credentialSubject.person.givenName": "Alice",
		}, true)
		require.NoError(t, err)
		require.Len(t, actualVPs, 1)
		assert.Equal(t, vpAlice.ID.String(), actualVPs[0].ID.String())
	})
	t.Run("find all", func(t *testing.T) {
		vps := []vc.VerifiablePresentation{vpAlice, vpBob}
		c := setupStore(t, storageEngine.GetSQLDatabase())
		for _, vp := range vps {
			_, err := c.add(testServiceID, vp, testSeed, 0)
			require.NoError(t, err)
		}

		actualVPs, err := c.search(testServiceID, map[string]string{}, true)
		require.NoError(t, err)
		require.Len(t, actualVPs, 2)

		t.Run("wildcard", func(t *testing.T) {
			actualVPs, err = c.search(testServiceID, map[string]string{"credentialSubject.person.givenName": "*"}, true)
			require.NoError(t, err)
			require.Len(t, actualVPs, 2)
		})
		t.Run("wildcard postfix", func(t *testing.T) {
			actualVPs, err = c.search(testServiceID, map[string]string{"credentialSubject.person.givenName": "A*"}, true)
			require.NoError(t, err)
			require.Len(t, actualVPs, 1)
		})
		t.Run("validated", func(t *testing.T) {
			actualVPs, err = c.search(testServiceID, map[string]string{}, false)
			require.NoError(t, err)
			require.Len(t, actualVPs, 0)
		})
	})
	t.Run("not found", func(t *testing.T) {
		vps := []vc.VerifiablePresentation{vpAlice, vpBob}
		c := setupStore(t, storageEngine.GetSQLDatabase())
		for _, vp := range vps {
			_, err := c.add(testServiceID, vp, testSeed, 0)
			require.NoError(t, err)
		}
		actualVPs, err := c.search(testServiceID, map[string]string{
			"credentialSubject.person.givenName": "Charlie",
		}, true)
		require.NoError(t, err)
		require.Len(t, actualVPs, 0)

		t.Run("wildcard", func(t *testing.T) {
			actualVPs, err = c.search(testServiceID, map[string]string{"credentialSubject.person.noName": "*"}, true)
			require.NoError(t, err)
			require.Len(t, actualVPs, 0)
		})

	})
}

func Test_sqlStore_getSubjectsToBeRefreshed(t *testing.T) {
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())
	t.Cleanup(func() {
		_ = storageEngine.Shutdown()
	})

	now := time.Now()
	t.Run("empty list", func(t *testing.T) {
		c := setupStore(t, storageEngine.GetSQLDatabase())
		candidates, err := c.getSubjectsToBeRefreshed(now)
		require.NoError(t, err)
		assert.Empty(t, candidates)
	})
	t.Run("1 entry, not stale", func(t *testing.T) {
		c := setupStore(t, storageEngine.GetSQLDatabase())
		require.NoError(t, c.updatePresentationRefreshTime(testServiceID, aliceSubject, nil, &now))
		candidates, err := c.getSubjectsToBeRefreshed(time.Now().Add(-1 * time.Hour))
		require.NoError(t, err)
		assert.Empty(t, candidates)
	})
	t.Run("1 entry, stale with holderCredential", func(t *testing.T) {
		c := setupStore(t, storageEngine.GetSQLDatabase())
		require.NoError(t, c.updatePresentationRefreshTime(testServiceID, aliceSubject, defaultRegistrationParams(aliceSubject), &now))
		candidates, err := c.getSubjectsToBeRefreshed(time.Now().Add(time.Hour))
		require.NoError(t, err)
		assert.Equal(t, []refreshCandidate{{testServiceID, aliceSubject, defaultRegistrationParams(aliceSubject)}}, candidates)
	})
	t.Run("1 entry, stale", func(t *testing.T) {
		c := setupStore(t, storageEngine.GetSQLDatabase())
		require.NoError(t, c.updatePresentationRefreshTime(testServiceID, aliceSubject, nil, &now))
		candidates, err := c.getSubjectsToBeRefreshed(time.Now().Add(time.Hour))
		require.NoError(t, err)
		assert.Equal(t, []refreshCandidate{{testServiceID, aliceSubject, nil}}, candidates)
	})
	t.Run("does not return removed entry", func(t *testing.T) {
		c := setupStore(t, storageEngine.GetSQLDatabase())
		require.NoError(t, c.updatePresentationRefreshTime(testServiceID, aliceSubject, nil, &now))

		// Assert it's there
		candidates, err := c.getSubjectsToBeRefreshed(time.Now().Add(time.Hour))
		require.NoError(t, err)
		assert.Equal(t, []refreshCandidate{{testServiceID, aliceSubject, nil}}, candidates)

		// Remove it
		require.NoError(t, c.updatePresentationRefreshTime(testServiceID, aliceSubject, nil, nil))
		candidates, err = c.getSubjectsToBeRefreshed(time.Now().Add(time.Hour))
		require.NoError(t, err)
		assert.Empty(t, candidates)
	})
}

func Test_sqlStore_getPresentationRefreshTime(t *testing.T) {
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())

	t.Run("no entry", func(t *testing.T) {
		c := setupStore(t, storageEngine.GetSQLDatabase())
		ts, err := c.getPresentationRefreshRecord(testServiceID, aliceSubject)
		require.NoError(t, err)
		assert.Nil(t, ts)
	})
	t.Run("entry exists", func(t *testing.T) {
		c := setupStore(t, storageEngine.GetSQLDatabase())
		now := time.Now().Truncate(time.Second)
		require.NoError(t, c.updatePresentationRefreshTime(testServiceID, aliceSubject, nil, &now))
		ts, err := c.getPresentationRefreshRecord(testServiceID, aliceSubject)
		require.NoError(t, err)
		require.NotNil(t, ts)
		assert.Equal(t, int(now.Unix()), ts.NextRefresh)

		t.Run("error is preloaded", func(t *testing.T) {
			require.NoError(t, c.setPresentationRefreshError(testServiceID, aliceSubject, assert.AnError))

			ts, err := c.getPresentationRefreshRecord(testServiceID, aliceSubject)

			require.NoError(t, err)
			require.NotNil(t, ts)
			assert.Equal(t, assert.AnError.Error(), ts.PresentationRefreshError.Error)
		})
	})
}

func Test_sqlStore_setPresentationRefreshError(t *testing.T) {
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())

	t.Run("store", func(t *testing.T) {
		c := setupStore(t, storageEngine.GetSQLDatabase())

		require.NoError(t, c.updatePresentationRefreshTime(testServiceID, aliceSubject, nil, to.Ptr(time.Now().Add(time.Second))))
		require.NoError(t, c.setPresentationRefreshError(testServiceID, aliceSubject, assert.AnError))

		// Check if the error is stored
		refreshError := getPresentationRefreshError(t, c.db, testServiceID, aliceSubject)

		assert.Equal(t, refreshError.Error, assert.AnError.Error())
		assert.True(t, refreshError.LastOccurrence > int(time.Now().Add(-1*time.Second).Unix()))
	})
	t.Run("deletePresentationRecord", func(t *testing.T) {
		c := setupStore(t, storageEngine.GetSQLDatabase())
		require.NoError(t, c.updatePresentationRefreshTime(testServiceID, aliceSubject, nil, to.Ptr(time.Now().Add(time.Second))))
		require.NoError(t, c.setPresentationRefreshError(testServiceID, aliceSubject, assert.AnError))
		require.NoError(t, c.setPresentationRefreshError(testServiceID, aliceSubject, nil))

		refreshError := getPresentationRefreshError(t, c.db, testServiceID, aliceSubject)

		assert.Nil(t, refreshError)
	})
}

func Test_sqlStore_getSubjectVPsOnService(t *testing.T) {
	// create VPs that have credentials for both Alice and Bob
	visitor := func(claims map[string]interface{}, vp *vc.VerifiablePresentation) {
		claims[jwt.AudienceKey] = []string{testServiceID}
	}

	vpAlice2 := createPresentationCustom(aliceDID, visitor, vcAlice, vcBob)
	vpBob2 := createPresentationCustom(bobDID, visitor, vcAlice, vcBob)

	// setup store
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())
	t.Cleanup(func() {
		_ = storageEngine.Shutdown()
	})
	c := setupStore(t, storageEngine.GetSQLDatabase())
	_, err := c.add(testServiceID, vpAlice2, testSeed, 0)
	require.NoError(t, err)
	_, err = c.add(testServiceID, vpBob2, testSeed, 0)
	require.NoError(t, err)

	t.Run("ok - single", func(t *testing.T) {
		vps, err := c.getSubjectVPsOnService(testServiceID, []did.DID{aliceDID})
		require.NoError(t, err)
		assert.Equal(t, map[did.DID][]vc.VerifiablePresentation{aliceDID: {vpAlice2}}, vps)
	})
	t.Run("ok - multi", func(t *testing.T) {
		vps, err := c.getSubjectVPsOnService(testServiceID, []did.DID{aliceDID, unsupportedDID, bobDID})
		require.NoError(t, err)
		assert.Equal(t, map[did.DID][]vc.VerifiablePresentation{aliceDID: {vpAlice2}, unsupportedDID: {}, unsupportedDID: nil, bobDID: {vpBob2}}, vps)
	})
}

func Test_sqlStore_wipeOnSeedChange(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())
	t.Cleanup(func() {
		_ = storageEngine.Shutdown()
	})

	t.Run("empty database", func(t *testing.T) {
		c := setupStore(t, storageEngine.GetSQLDatabase())
		err := c.wipeOnSeedChange(testServiceID, "other")
		require.NoError(t, err)
	})
	t.Run("1 entry wiped, 1 remains", func(t *testing.T) {
		c := setupStore(t, storageEngine.GetSQLDatabase())
		_, err := c.add(testServiceID, vpAlice, testSeed, 0)
		require.NoError(t, err)
		_, err = c.add("other", vpAlice, testSeed, 0)
		require.NoError(t, err)

		err = c.wipeOnSeedChange(testServiceID, "other")
		require.NoError(t, err)

		vps, err := c.search(testServiceID, map[string]string{}, true)
		require.NoError(t, err)
		require.Len(t, vps, 0)
		vps, err = c.search("other", map[string]string{}, true)
		require.NoError(t, err)
		require.Len(t, vps, 1)
	})
}

func Test_sqlStore_updateValidated(t *testing.T) {
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())
	t.Cleanup(func() {
		_ = storageEngine.Shutdown()
	})

	c := setupStore(t, storageEngine.GetSQLDatabase())
	_, err := c.add(testServiceID, vpAlice, testSeed, 0)
	require.NoError(t, err)

	result, err := c.allPresentations(true)
	require.NoError(t, err)
	assert.Len(t, result, 0)
	result, err = c.allPresentations(false)
	require.NoError(t, err)
	assert.Len(t, result, 1)

	t.Run("validated", func(t *testing.T) {
		err = c.updateValidated(result)
		require.NoError(t, err)

		result, err = c.allPresentations(false)
		require.NoError(t, err)
		assert.Len(t, result, 0)
		result, err = c.allPresentations(true)
		require.NoError(t, err)
		assert.Len(t, result, 1)
	})
}

func Test_sqlStore_delete(t *testing.T) {
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())
	t.Cleanup(func() {
		_ = storageEngine.Shutdown()
	})

	c := setupStore(t, storageEngine.GetSQLDatabase())
	_, err := c.add(testServiceID, vpAlice, testSeed, 0)
	require.NoError(t, err)
	presentations, _ := c.allPresentations(false)
	require.Len(t, presentations, 1)

	err = c.deletePresentationRecord(presentations[0].ID)

	require.NoError(t, err)

	result, err := c.allPresentations(false)
	require.NoError(t, err)
	assert.Len(t, result, 0)
}

func setupStore(t *testing.T, db *gorm.DB) *sqlStore {
	resetStore(t, db)
	defs := testDefinitions()
	store, err := newSQLStore(db, defs)
	require.NoError(t, err)
	return store
}

func resetStore(t *testing.T, db *gorm.DB) {
	// related tables are emptied due to on-deletePresentationRecord-cascade clause
	tableNames := []string{"discovery_service", "discovery_presentation", "discovery_credential", "credential", "credential_prop"}
	for _, tableName := range tableNames {
		require.NoError(t, db.Exec("DELETE FROM "+tableName).Error)
	}
}

func getPresentationRefreshError(t *testing.T, db *gorm.DB, serviceID string, subjectID string) *presentationRefreshError {
	var row presentationRefreshError
	err := db.Find(&row, "service_id = ? AND subject_id = ?", serviceID, subjectID).Error
	require.NoError(t, err)
	if row.LastOccurrence == 0 {
		return nil
	}
	return &row
}
