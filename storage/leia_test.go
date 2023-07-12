/*
 * Copyright (C) 2022 Nuts community
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

package storage

import (
	"context"
	"crypto/sha1"
	"encoding/json"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/go-leia/v4"
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/go-stoabs/bbolt"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"path"
	"testing"
)

func Test_leiaIssuerStore_handleRestore(t *testing.T) {
	ctx := context.Background()

	configs := []LeiaBackupConfiguration{
		{
			BackupShelf:    "JSON",
			CollectionName: "JSON",
			CollectionType: leia.JSONCollection,
			SearchQuery:    leia.NewJSONPath("id"),
		},
		{
			BackupShelf:    "JSONLD",
			CollectionName: "JSONLD",
			CollectionType: leia.JSONLDCollection,
			SearchQuery:    leia.NewIRIPath(), // empty slice means @id on root resource
		},
	}

	document := []byte(jsonld.TestOrganizationCredential)
	ref := defaultReference(document)
	vc := vc.VerifiableCredential{}
	_ = json.Unmarshal(document, &vc)

	for _, backupConfig := range configs {
		t.Run(backupConfig.CollectionName, func(t *testing.T) {
			t.Run("both empty", func(t *testing.T) {
				store := newStore(t, backupConfig)
				collection := store.Collection(backupConfig.CollectionType, backupConfig.CollectionName)

				err := store.HandleRestore()

				require.NoError(t, err)
				assert.False(t, storePresent(collection, backupConfig))
				assert.False(t, store.backupStorePresent(backupConfig.BackupShelf))
			})

			t.Run("both present", func(t *testing.T) {
				store := newStore(t, backupConfig)
				collection := store.Collection(backupConfig.CollectionType, backupConfig.CollectionName)
				err := collection.Add([]leia.Document{document})
				require.NoError(t, err)

				err = store.HandleRestore()

				assert.NoError(t, err)
				assert.True(t, storePresent(collection, backupConfig))
				assert.True(t, store.backupStorePresent(backupConfig.BackupShelf))
			})

			t.Run("only backup present", func(t *testing.T) {
				testDir := io.TestDirectory(t)
				backupStorePath := path.Join(testDir, "vcr", "backup-private-credentials.db")
				backupStore, err := bbolt.CreateBBoltStore(backupStorePath)
				require.NoError(t, err)
				err = backupStore.WriteShelf(ctx, backupConfig.BackupShelf, func(writer stoabs.Writer) error {
					return writer.Put(stoabs.BytesKey(ref), document)
				})
				require.NoError(t, err)
				err = backupStore.Close(context.Background())
				require.NoError(t, err)
				store := newStoreInDir(t, testDir, backupConfig)

				err = store.handleRestore(backupConfig)

				require.NoError(t, err)
				assertCredential(t, store, backupConfig, vc)
			})

			t.Run("only index present", func(t *testing.T) {
				store := newStore(t, backupConfig)
				collection := store.store.Collection(backupConfig.CollectionType, backupConfig.CollectionName)
				err := collection.Add([]leia.Document{document})
				require.NoError(t, err)

				err = store.handleRestore(backupConfig)

				require.NoError(t, err)
				_ = store.backup.ReadShelf(ctx, backupConfig.BackupShelf, func(reader stoabs.Reader) error {
					val, err := reader.Get(stoabs.BytesKey(ref))
					assert.NoError(t, err)
					assert.NotNil(t, val)
					return nil
				})
			})
		})
	}
}

func assertCredential(t *testing.T, store *kvBackedLeiaStore, config LeiaBackupConfiguration, expected vc.VerifiableCredential) {
	query := leia.New(leia.Eq(config.SearchQuery, leia.MustParseScalar(expected.ID.String())))
	results, err := store.store.Collection(config.CollectionType, config.CollectionName).Find(context.Background(), query)
	require.NoError(t, err)
	require.Len(t, results, 1)
	result := results[0]
	credential := &vc.VerifiableCredential{}
	err = json.Unmarshal(result, credential)
	require.NoError(t, err)
	assert.Equal(t, expected.ID, credential.ID)
}

func newStore(t *testing.T, backupConfig LeiaBackupConfiguration) *kvBackedLeiaStore {
	testDir := io.TestDirectory(t)
	return newStoreInDir(t, testDir, backupConfig)
}

func newStoreInDir(t *testing.T, testDir string, backupConfig LeiaBackupConfiguration) *kvBackedLeiaStore {
	issuerStorePath := path.Join(testDir, "vcr", "private-credentials.db")
	backupStorePath := path.Join(testDir, "vcr", "backup-private-credentials.db")
	backupStore, err := bbolt.CreateBBoltStore(backupStorePath)
	require.NoError(t, err)
	leiaStore, err := leia.NewStore(issuerStorePath)
	require.NoError(t, err)
	store, err := NewKVBackedLeiaStore(leiaStore, backupStore)
	require.NoError(t, err)
	// add backup config
	store.AddConfiguration(backupConfig)
	// add an index
	idIndex := leiaStore.Collection(backupConfig.CollectionType, backupConfig.CollectionName).NewIndex("issuedVCByID",
		leia.NewFieldIndexer(backupConfig.SearchQuery))
	err = leiaStore.Collection(backupConfig.CollectionType, backupConfig.CollectionName).AddIndex(idIndex)
	require.NoError(t, err)
	// cleanup
	t.Cleanup(func() {
		_ = store.Close()
	})

	return store.(*kvBackedLeiaStore)
}

func defaultReference(doc leia.Document) leia.Reference {
	s := sha1.Sum(doc)
	var b = make([]byte, len(s))
	copy(b, s[:])

	return b
}
