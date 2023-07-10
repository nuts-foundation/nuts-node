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
	"github.com/nuts-foundation/go-leia/v3"
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/go-stoabs/bbolt"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"path"
	"testing"
)

var backupConfigJSON = LeiaBackupConfiguration{
	BackupShelf:    "JSON",
	CollectionName: "JSON",
	CollectionType: JSONCollectionType,
	SearchQuery:    leia.NewJSONPath("id"),
}
var backupConfigJSONLD = LeiaBackupConfiguration{
	BackupShelf:    "JSONLD",
	CollectionName: "JSONLD",
	CollectionType: JSONLDCollectionType,
	SearchQuery:    leia.NewIRIPath(), // empty slice means @id on root resource
}

func Test_leiaIssuerStore_handleRestore(t *testing.T) {
	ctx := context.Background()

	t.Run("JSON collection", func(t *testing.T) {
		collectionName := "JSON"
		backupShelf := "JSON"
		document := []byte(jsonld.TestOrganizationCredential)
		ref := defaultReference(document)
		vc := vc.VerifiableCredential{}
		_ = json.Unmarshal(document, &vc)

		t.Run("both empty", func(t *testing.T) {
			store := newJSONStore(t)
			collection := store.JSONCollection(collectionName)

			err := store.HandleRestore()

			require.NoError(t, err)
			assert.False(t, storePresent(collection, backupConfigJSON))
			assert.False(t, store.backupStorePresent(backupShelf))
		})

		t.Run("both present", func(t *testing.T) {
			store := newJSONStore(t)
			collection := store.JSONCollection(collectionName)
			err := collection.Add([]leia.Document{document})
			require.NoError(t, err)

			err = store.HandleRestore()

			assert.NoError(t, err)
			assert.True(t, storePresent(collection, backupConfigJSON))
			assert.True(t, store.backupStorePresent(backupShelf))
		})

		t.Run("only backup present", func(t *testing.T) {
			testDir := io.TestDirectory(t)
			backupStorePath := path.Join(testDir, "vcr", "backup-private-credentials.db")
			backupStore, err := bbolt.CreateBBoltStore(backupStorePath)
			require.NoError(t, err)
			err = backupStore.WriteShelf(ctx, backupShelf, func(writer stoabs.Writer) error {
				return writer.Put(stoabs.BytesKey(ref), document)
			})
			require.NoError(t, err)
			err = backupStore.Close(context.Background())
			require.NoError(t, err)
			store := newJSONStoreInDir(t, testDir)

			err = store.handleRestore(backupConfigJSON)

			require.NoError(t, err)
			assertCredential(t, store, backupConfigJSON, vc)
		})

		t.Run("only index present", func(t *testing.T) {
			store := newJSONStore(t)
			collection := store.store.JSONCollection(collectionName)
			err := collection.Add([]leia.Document{document})
			require.NoError(t, err)

			err = store.handleRestore(backupConfigJSON)

			require.NoError(t, err)
			_ = store.backup.ReadShelf(ctx, backupShelf, func(reader stoabs.Reader) error {
				val, err := reader.Get(stoabs.BytesKey(ref))
				assert.NoError(t, err)
				assert.NotNil(t, val)
				return nil
			})
		})
	})

	t.Run("JSONLD collection", func(t *testing.T) {
		collectionName := "JSONLD"
		backupShelf := "JSONLD"
		document := []byte(jsonld.TestOrganizationCredential)
		ref := defaultReference(document)
		vc := vc.VerifiableCredential{}
		_ = json.Unmarshal(document, &vc)

		t.Run("both empty", func(t *testing.T) {
			store := newJSONLDStore(t)
			collection := store.JSONLDCollection(collectionName)

			err := store.HandleRestore()

			require.NoError(t, err)
			assert.False(t, storePresent(collection, backupConfigJSONLD))
			assert.False(t, store.backupStorePresent(backupShelf))
		})

		t.Run("both present", func(t *testing.T) {
			store := newJSONLDStore(t)
			collection := store.JSONLDCollection(collectionName)
			err := collection.Add([]leia.Document{document})
			require.NoError(t, err)

			err = store.HandleRestore()

			assert.NoError(t, err)
			assert.True(t, storePresent(collection, backupConfigJSONLD))
			assert.True(t, store.backupStorePresent(backupShelf))
		})

		t.Run("only backup present", func(t *testing.T) {
			testDir := io.TestDirectory(t)
			backupStorePath := path.Join(testDir, "vcr", "backup-private-credentials.db")
			backupStore, err := bbolt.CreateBBoltStore(backupStorePath)
			require.NoError(t, err)
			err = backupStore.WriteShelf(ctx, backupShelf, func(writer stoabs.Writer) error {
				return writer.Put(stoabs.BytesKey(ref), document)
			})
			require.NoError(t, err)
			err = backupStore.Close(context.Background())
			require.NoError(t, err)
			store := newJSONLDStoreInDir(t, testDir)

			err = store.handleRestore(backupConfigJSONLD)

			require.NoError(t, err)
			assertCredentialJSONLD(t, store, backupConfigJSONLD, vc)
		})

		t.Run("only index present", func(t *testing.T) {
			store := newJSONLDStore(t)
			collection := store.store.JSONLDCollection(collectionName)
			err := collection.Add([]leia.Document{document})
			require.NoError(t, err)

			err = store.handleRestore(backupConfigJSONLD)

			require.NoError(t, err)
			_ = store.backup.ReadShelf(ctx, backupShelf, func(reader stoabs.Reader) error {
				val, err := reader.Get(stoabs.BytesKey(ref))
				assert.NoError(t, err)
				assert.NotNil(t, val)
				return nil
			})
		})
	})
}

func assertCredential(t *testing.T, store *kvBackedLeiaStore, config LeiaBackupConfiguration, expected vc.VerifiableCredential) {
	query := leia.New(leia.Eq(config.SearchQuery, leia.MustParseScalar(expected.ID.String())))
	results, err := store.store.JSONCollection(config.CollectionName).Find(context.Background(), query)
	require.NoError(t, err)
	require.Len(t, results, 1)
	result := results[0]
	credential := &vc.VerifiableCredential{}
	err = json.Unmarshal(result, credential)
	require.NoError(t, err)
	assert.Equal(t, expected.ID, credential.ID)
}

func assertCredentialJSONLD(t *testing.T, store *kvBackedLeiaStore, config LeiaBackupConfiguration, expected vc.VerifiableCredential) {
	query := leia.New(leia.Eq(config.SearchQuery, leia.MustParseScalar(expected.ID.String())))
	results, err := store.store.JSONLDCollection(config.CollectionName).Find(context.Background(), query)
	require.NoError(t, err)
	require.Len(t, results, 1)
	result := results[0]
	credential := &vc.VerifiableCredential{}
	err = json.Unmarshal(result, credential)
	require.NoError(t, err)
	assert.Equal(t, expected.ID, credential.ID)
}

func newJSONStore(t *testing.T) *kvBackedLeiaStore {
	testDir := io.TestDirectory(t)
	return newJSONStoreInDir(t, testDir)
}

func newJSONStoreInDir(t *testing.T, testDir string) *kvBackedLeiaStore {
	issuerStorePath := path.Join(testDir, "vcr", "private-credentials.db")
	backupStorePath := path.Join(testDir, "vcr", "backup-private-credentials.db")
	backupStore, err := bbolt.CreateBBoltStore(backupStorePath)
	require.NoError(t, err)
	leiaStore, err := leia.NewStore(issuerStorePath)
	require.NoError(t, err)
	store, err := NewKVBackedLeiaStore(leiaStore, backupStore)
	require.NoError(t, err)
	// add backup config
	store.AddConfiguration(backupConfigJSON)
	// add an index
	idIndex := leiaStore.JSONCollection("JSON").NewIndex("issuedVCByID",
		leia.NewFieldIndexer(backupConfigJSON.SearchQuery))
	err = leiaStore.JSONCollection("JSON").AddIndex(idIndex)
	require.NoError(t, err)
	// cleanup
	t.Cleanup(func() {
		_ = store.Close()
	})

	return store.(*kvBackedLeiaStore)
}

func newJSONLDStore(t *testing.T) *kvBackedLeiaStore {
	testDir := io.TestDirectory(t)
	return newJSONLDStoreInDir(t, testDir)
}

func newJSONLDStoreInDir(t *testing.T, testDir string) *kvBackedLeiaStore {
	issuerStorePath := path.Join(testDir, "vcr", "private-credentials.db")
	backupStorePath := path.Join(testDir, "vcr", "backup-private-credentials.db")
	backupStore, err := bbolt.CreateBBoltStore(backupStorePath)
	require.NoError(t, err)
	leiaStore, err := leia.NewStore(issuerStorePath)
	require.NoError(t, err)
	store, err := NewKVBackedLeiaStore(leiaStore, backupStore)
	require.NoError(t, err)
	// add backup config
	store.AddConfiguration(backupConfigJSONLD)
	// add an index
	idIndex := leiaStore.JSONLDCollection("JSONLD").NewIndex("issuedVCByID",
		leia.NewFieldIndexer(backupConfigJSONLD.SearchQuery)) // empty path means root resource which matches @id
	err = leiaStore.JSONLDCollection("JSONLD").AddIndex(idIndex)
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
