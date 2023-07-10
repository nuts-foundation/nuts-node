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

const (
	backupShelf    = "backup"
	collectionName = "credentials"
)

var backupConfig = LeiaBackupConfiguration{
	BackupShelf:    backupShelf,
	CollectionName: collectionName,
	CollectionType: JSONCollectionType,
	SearchPath:     "id",
}

func Test_leiaIssuerStore_handleRestore(t *testing.T) {
	ctx := context.Background()
	t.Run("credentials", func(t *testing.T) {
		document := []byte(jsonld.TestCredential)
		ref := defaultReference(document)
		vc := vc.VerifiableCredential{}
		_ = json.Unmarshal(document, &vc)

		t.Run("both empty", func(t *testing.T) {
			store := newStore(t)
			collection := store.JSONCollection(collectionName)

			err := store.HandleRestore()

			require.NoError(t, err)
			assert.False(t, storePresent(collection, "id"))
			assert.False(t, store.backupStorePresent(backupShelf))
		})

		t.Run("both present", func(t *testing.T) {
			store := newStore(t)
			collection := store.JSONCollection(collectionName)
			err := collection.Add([]leia.Document{document})
			require.NoError(t, err)

			err = store.HandleRestore()

			assert.NoError(t, err)
			assert.True(t, storePresent(collection, "id"))
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
			store := newStoreInDir(t, testDir)

			err = store.handleRestore(backupConfig)

			require.NoError(t, err)
			assertCredential(t, store, backupConfig, vc)
		})

		t.Run("only index present", func(t *testing.T) {
			store := newStore(t)
			collection := store.JSONCollection(collectionName)
			err := collection.Add([]leia.Document{document})
			require.NoError(t, err)

			err = store.handleRestore(backupConfig)

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
	query := leia.New(leia.Eq(leia.NewJSONPath(config.SearchPath), leia.MustParseScalar(expected.ID.String())))
	results, err := store.store.JSONCollection(config.CollectionName).Find(context.Background(), query)
	require.NoError(t, err)
	require.Len(t, results, 1)
	result := results[0]
	credential := &vc.VerifiableCredential{}
	err = json.Unmarshal(result, credential)
	require.NoError(t, err)
	assert.Equal(t, expected.ID, credential.ID)
}

func newStore(t *testing.T) *kvBackedLeiaStore {
	testDir := io.TestDirectory(t)
	return newStoreInDir(t, testDir)
}

func newStoreInDir(t *testing.T, testDir string) *kvBackedLeiaStore {
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
	idIndex := leiaStore.JSONCollection(collectionName).NewIndex("issuedVCByID",
		leia.NewFieldIndexer(leia.NewJSONPath("id")))
	err = leiaStore.JSONCollection(collectionName).AddIndex(idIndex)
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
