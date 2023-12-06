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
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"sync"
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

func Test_sqlStore_add(t *testing.T) {
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())

	t.Run("no credentials in presentation", func(t *testing.T) {
		m := setupStore(t, storageEngine.GetSQLDatabase())
		err := m.add(testServiceID, createPresentation(aliceDID), nil)
		assert.NoError(t, err)
	})
	t.Run("with indexable properties in credential", func(t *testing.T) {
		m := setupStore(t, storageEngine.GetSQLDatabase())
		err := m.add(testServiceID, createPresentation(aliceDID, createCredential(authorityDID, aliceDID, map[string]interface{}{
			"name":         "Alice",
			"placeOfBirth": "Bristol",
		}, nil)), nil)
		assert.NoError(t, err)

		var actual []credentialPropertyRecord
		assert.NoError(t, m.db.Find(&actual).Error)
		require.Len(t, actual, 2)
		assert.Equal(t, "Alice", sliceToMap(actual)["credentialSubject.name"])
		assert.Equal(t, "Bristol", sliceToMap(actual)["credentialSubject.placeOfBirth"])
	})
	t.Run("with non-indexable properties in credential", func(t *testing.T) {
		m := setupStore(t, storageEngine.GetSQLDatabase())
		err := m.add(testServiceID, createPresentation(aliceDID, createCredential(authorityDID, aliceDID, map[string]interface{}{
			"name": "Alice",
			"age":  35,
		}, nil)), nil)
		assert.NoError(t, err)

		var actual []credentialPropertyRecord
		assert.NoError(t, m.db.Find(&actual).Error)
		require.Len(t, actual, 1)
		assert.Equal(t, "Alice", sliceToMap(actual)["credentialSubject.name"])
	})
	t.Run("without indexable properties in credential", func(t *testing.T) {
		m := setupStore(t, storageEngine.GetSQLDatabase())
		presentation := createCredential(authorityDID, aliceDID, map[string]interface{}{}, nil)
		err := m.add(testServiceID, createPresentation(aliceDID, presentation), nil)
		assert.NoError(t, err)

		var actual []credentialPropertyRecord
		assert.NoError(t, m.db.Find(&actual).Error)
		assert.Empty(t, actual)
	})
	t.Run("replaces previous presentation of same subject", func(t *testing.T) {
		m := setupStore(t, storageEngine.GetSQLDatabase())

		secondVP := createPresentation(aliceDID, vcAlice)
		require.NoError(t, m.add(testServiceID, vpAlice, nil))
		require.NoError(t, m.add(testServiceID, secondVP, nil))

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

	t.Run("empty list, empty tag", func(t *testing.T) {
		m := setupStore(t, storageEngine.GetSQLDatabase())
		presentations, tag, err := m.get(testServiceID, nil)
		assert.NoError(t, err)
		assert.Empty(t, presentations)
		expectedTag := tagForTimestamp(t, m, testServiceID, 0)
		assert.Equal(t, expectedTag, *tag)
	})
	t.Run("1 entry, empty tag", func(t *testing.T) {
		m := setupStore(t, storageEngine.GetSQLDatabase())
		require.NoError(t, m.add(testServiceID, vpAlice, nil))
		presentations, tag, err := m.get(testServiceID, nil)
		assert.NoError(t, err)
		assert.Equal(t, []vc.VerifiablePresentation{vpAlice}, presentations)
		expectedTag := tagForTimestamp(t, m, testServiceID, 1)
		assert.Equal(t, expectedTag, *tag)
	})
	t.Run("2 entries, empty tag", func(t *testing.T) {
		m := setupStore(t, storageEngine.GetSQLDatabase())
		require.NoError(t, m.add(testServiceID, vpAlice, nil))
		require.NoError(t, m.add(testServiceID, vpBob, nil))
		presentations, tag, err := m.get(testServiceID, nil)
		assert.NoError(t, err)
		assert.Equal(t, []vc.VerifiablePresentation{vpAlice, vpBob}, presentations)
		expectedTS := tagForTimestamp(t, m, testServiceID, 2)
		assert.Equal(t, expectedTS, *tag)
	})
	t.Run("2 entries, start after first", func(t *testing.T) {
		m := setupStore(t, storageEngine.GetSQLDatabase())
		require.NoError(t, m.add(testServiceID, vpAlice, nil))
		require.NoError(t, m.add(testServiceID, vpBob, nil))
		ts := tagForTimestamp(t, m, testServiceID, 1)
		presentations, tag, err := m.get(testServiceID, &ts)
		assert.NoError(t, err)
		assert.Equal(t, []vc.VerifiablePresentation{vpBob}, presentations)
		expectedTS := tagForTimestamp(t, m, testServiceID, 2)
		assert.Equal(t, expectedTS, *tag)
	})
	t.Run("2 entries, start after end", func(t *testing.T) {
		m := setupStore(t, storageEngine.GetSQLDatabase())
		require.NoError(t, m.add(testServiceID, vpAlice, nil))
		require.NoError(t, m.add(testServiceID, vpBob, nil))
		expectedTag := tagForTimestamp(t, m, testServiceID, 2)
		presentations, tag, err := m.get(testServiceID, &expectedTag)
		assert.NoError(t, err)
		assert.Equal(t, []vc.VerifiablePresentation{}, presentations)
		expectedTag = tagForTimestamp(t, m, testServiceID, 0)
		assert.Equal(t, expectedTag, *tag)
	})
}

func Test_sqlStore_search(t *testing.T) {
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())
	t.Cleanup(func() {
		_ = storageEngine.Shutdown()
	})

	type testCase struct {
		name        string
		inputVPs    []vc.VerifiablePresentation
		query       map[string]string
		expectedVPs []string
	}
	testCases := []testCase{
		{
			name:     "issuer",
			inputVPs: []vc.VerifiablePresentation{vpAlice},
			query: map[string]string{
				"issuer": authorityDID.String(),
			},
			expectedVPs: []string{vpAlice.ID.String()},
		},
		{
			name:     "id",
			inputVPs: []vc.VerifiablePresentation{vpAlice},
			query: map[string]string{
				"id": vcAlice.ID.String(),
			},
			expectedVPs: []string{vpAlice.ID.String()},
		},
		{
			name:     "type",
			inputVPs: []vc.VerifiablePresentation{vpAlice},
			query: map[string]string{
				"type": "TestCredential",
			},
			expectedVPs: []string{vpAlice.ID.String()},
		},
		{
			name:     "credentialSubject.id",
			inputVPs: []vc.VerifiablePresentation{vpAlice},
			query: map[string]string{
				"credentialSubject.id": aliceDID.String(),
			},
			expectedVPs: []string{vpAlice.ID.String()},
		},
		{
			name:     "1 property",
			inputVPs: []vc.VerifiablePresentation{vpAlice},
			query: map[string]string{
				"credentialSubject.person.givenName": "Alice",
			},
			expectedVPs: []string{vpAlice.ID.String()},
		},
		{
			name:     "2 properties",
			inputVPs: []vc.VerifiablePresentation{vpAlice},
			query: map[string]string{
				"credentialSubject.person.givenName":  "Alice",
				"credentialSubject.person.familyName": "Jones",
			},
			expectedVPs: []string{vpAlice.ID.String()},
		},
		{
			name:     "properties and base properties",
			inputVPs: []vc.VerifiablePresentation{vpAlice},
			query: map[string]string{
				"issuer":                             authorityDID.String(),
				"credentialSubject.person.givenName": "Alice",
			},
			expectedVPs: []string{vpAlice.ID.String()},
		},
		{
			name:     "wildcard postfix",
			inputVPs: []vc.VerifiablePresentation{vpAlice, vpBob},
			query: map[string]string{
				"credentialSubject.person.familyName": "Jo*",
			},
			expectedVPs: []string{vpAlice.ID.String(), vpBob.ID.String()},
		},
		{
			name:     "wildcard prefix",
			inputVPs: []vc.VerifiablePresentation{vpAlice, vpBob},
			query: map[string]string{
				"credentialSubject.person.givenName": "*ce",
			},
			expectedVPs: []string{vpAlice.ID.String()},
		},
		{
			name:     "wildcard midway (no interpreted as wildcard)",
			inputVPs: []vc.VerifiablePresentation{vpAlice, vpBob},
			query: map[string]string{
				"credentialSubject.person.givenName": "A*ce",
			},
			expectedVPs: []string{},
		},
		{
			name:     "just wildcard",
			inputVPs: []vc.VerifiablePresentation{vpAlice, vpBob},
			query: map[string]string{
				"id": "*",
			},
			expectedVPs: []string{vpAlice.ID.String(), vpBob.ID.String()},
		},
		{
			name:     "2 VPs, 1 match",
			inputVPs: []vc.VerifiablePresentation{vpAlice, vpBob},
			query: map[string]string{
				"credentialSubject.person.givenName": "Alice",
			},
			expectedVPs: []string{vpAlice.ID.String()},
		},
		{
			name:     "multiple matches",
			inputVPs: []vc.VerifiablePresentation{vpAlice, vpBob},
			query: map[string]string{
				"issuer": authorityDID.String(),
			},
			expectedVPs: []string{vpAlice.ID.String(), vpBob.ID.String()},
		},
		{
			name:     "no match",
			inputVPs: []vc.VerifiablePresentation{vpAlice},
			query: map[string]string{
				"credentialSubject.person.givenName": "Bob",
			},
			expectedVPs: []string{},
		},
		{
			name: "empty database",
			query: map[string]string{
				"credentialSubject.person.givenName": "Bob",
			},
			expectedVPs: []string{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			c := setupStore(t, storageEngine.GetSQLDatabase())
			for _, vp := range tc.inputVPs {
				err := c.add(testServiceID, vp, nil)
				require.NoError(t, err)
			}
			actualVPs, err := c.search(testServiceID, tc.query)
			require.NoError(t, err)
			require.Len(t, actualVPs, len(tc.expectedVPs))
			for _, expectedVP := range tc.expectedVPs {
				found := false
				for _, actualVP := range actualVPs {
					if actualVP.ID.String() == expectedVP {
						found = true
						break
					}
				}
				require.True(t, found, "expected to find VP with ID %s", expectedVP)
			}
		})
	}

	t.Run("concurrency", func(t *testing.T) {
		c := setupStore(t, storageEngine.GetSQLDatabase())
		wg := &sync.WaitGroup{}
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				err := c.add(testServiceID, createPresentation(aliceDID, vcAlice), nil)
				require.NoError(t, err)
			}()
		}
		wg.Wait()
	})
}

func setupStore(t *testing.T, db *gorm.DB) *sqlStore {
	resetStore(t, db)
	defs := testDefinitions()
	store, err := newSQLStore(db, defs, defs)
	require.NoError(t, err)
	return store
}

func resetStore(t *testing.T, db *gorm.DB) {
	underlyingDB, err := db.DB()
	require.NoError(t, err)
	// related tables are emptied due to on-delete-cascade clause
	_, err = underlyingDB.Exec("DELETE FROM discovery_service")
	require.NoError(t, err)
}

func sliceToMap(slice []credentialPropertyRecord) map[string]string {
	var result = make(map[string]string)
	for _, curr := range slice {
		result[curr.Key] = curr.Value
	}
	return result
}

func Test_generateSeed(t *testing.T) {
	for i := 0; i < 100; i++ {
		seed := generatePrefix()
		assert.Len(t, seed, 5)
		for _, char := range seed {
			assert.True(t, char >= 'A' && char <= 'Z')
		}
	}
}

func tagForTimestamp(t *testing.T, store *sqlStore, serviceID string, ts int) Tag {
	t.Helper()
	var service serviceRecord
	require.NoError(t, store.db.Find(&service, "id = ?", serviceID).Error)
	return Timestamp(ts).Tag(service.TagPrefix)
}
