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

package issuer

import (
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/test"
	"github.com/nuts-foundation/nuts-node/vcr/types"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"testing"
)

func Test_sqlStore_Diagnostics(t *testing.T) {
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())
	store := sqlStore{db: storageEngine.GetSQLDatabase()}

	err := store.StoreCredential(test.ValidNutsAuthorizationCredential(t))
	require.NoError(t, err)
	results := store.Diagnostics()

	require.Len(t, results, 1)
	require.Equal(t, "issued_credentials_count", results[0].Name())
	require.Equal(t, 1, results[0].Result())
}

func Test_sqlStore_GetCredential(t *testing.T) {
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())
	store := sqlStore{db: storageEngine.GetSQLDatabase()}

	t.Run("found", func(t *testing.T) {
		setupStore(t, store.db)
		credential := test.ValidNutsOrganizationCredential(t)
		err := store.StoreCredential(credential)
		require.NoError(t, err)

		loadedCredential, err := store.GetCredential(*credential.ID)
		require.NoError(t, err)
		require.Equal(t, credential.ID, loadedCredential.ID)
	})
	t.Run("not found", func(t *testing.T) {
		setupStore(t, store.db)

		result, err := store.GetCredential(ssi.MustParseURI("did:nuts:credential:123"))

		require.ErrorIs(t, err, types.ErrNotFound)
		require.Nil(t, result)
	})
}

func Test_sqlStore_GetRevocation(t *testing.T) {
	// not supported, always returns error
	result, err := sqlStore{}.GetRevocation(ssi.MustParseURI("did:nuts:revocation:123"))
	require.ErrorIs(t, err, types.ErrNotFound)
	require.Nil(t, result)
}

func Test_sqlStore_SearchCredential(t *testing.T) {
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())
	store := sqlStore{db: storageEngine.GetSQLDatabase()}
	subjectID := ssi.MustParseURI("did:nuts:CuE3qeFGGLhEAS3gKzhMCeqd1dGa9at5JCbmCfyMU2Ey")
	t.Run("not found", func(t *testing.T) {
		setupStore(t, store.db)

		result, err := store.SearchCredential(ssi.URI{}, did.DID{}, nil)

		require.NoError(t, err)
		require.Len(t, result, 0)
	})
	t.Run("found", func(t *testing.T) {
		setupStore(t, store.db)
		credential := test.ValidNutsOrganizationCredential(t)
		err := store.StoreCredential(credential)
		require.NoError(t, err)

		result, err := store.SearchCredential(credential.Type[0], did.MustParseDID(credential.Issuer.String()), nil)

		require.NoError(t, err)
		require.Len(t, result, 1)
	})
	t.Run("with subject", func(t *testing.T) {
		setupStore(t, store.db)
		credential := test.ValidNutsOrganizationCredential(t)
		err := store.StoreCredential(credential)
		require.NoError(t, err)

		result, err := store.SearchCredential(credential.Type[0], did.MustParseDID(credential.Issuer.String()), &subjectID)

		require.NoError(t, err)
		require.Len(t, result, 1)
	})
	t.Run("with non-matching subject", func(t *testing.T) {
		setupStore(t, store.db)
		credential := test.ValidNutsOrganizationCredential(t)
		err := store.StoreCredential(credential)
		require.NoError(t, err)
		subject := vdr.TestDIDA.URI()

		result, err := store.SearchCredential(credential.Type[0], did.MustParseDID(credential.Issuer.String()), &subject)

		require.NoError(t, err)
		require.Len(t, result, 0)
	})
}

func Test_sqlStore_StoreCredential(t *testing.T) {
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())
	store := sqlStore{db: storageEngine.GetSQLDatabase()}

	credential := test.ValidNutsAuthorizationCredential(t)
	err := store.StoreCredential(credential)
	require.NoError(t, err)
}

func Test_sqlStore_StoreRevocation(t *testing.T) {
	// Not supported
	err := sqlStore{}.StoreRevocation(credential.Revocation{})
	require.Error(t, err)
}

func setupStore(t *testing.T, db *gorm.DB) {
	require.NoError(t, db.Exec("DELETE FROM issued_credential").Error)
	// related tables are emptied due to on-delete-cascade clause
	require.NoError(t, db.Exec("DELETE FROM credential").Error)
}
