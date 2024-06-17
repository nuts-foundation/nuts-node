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

package didweb

import (
	"context"
	"crypto"
	"github.com/lestrrat-go/jwx/v2/jwk"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/audit"
	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/vdr/management"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"github.com/nuts-foundation/nuts-node/vdr/sql"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"strings"
	"testing"
)

var rootDID = did.MustParseDID("did:web:example.com")

const tenantPath = "iam"

var subjectDID = did.MustParseDID("did:web:example.com:iam:1234")
var ctx = context.Background()

func TestManager_Create(t *testing.T) {
	const keyJSON = `{
        "crv": "P-256",
        "kty": "EC",
        "x": "4VT-BXoTel3lvlwJRFFgN0XhWeSdziIzgHqE_J-o42k",
        "y": "yXwrpCkfKm44IcAI4INk_flMwFULonJeo595_g-dwwE"
      }`
	keyAsJWK, err := jwk.ParseKey([]byte(keyJSON))
	require.NoError(t, err)
	var publicKey crypto.PublicKey
	require.NoError(t, keyAsJWK.Raw(&publicKey))

	t.Run("assert build DID document", func(t *testing.T) {
		db := testDB(t)
		ctrl := gomock.NewController(t)
		keyStore := nutsCrypto.NewMockKeyStore(ctrl)
		keyStore.EXPECT().New(gomock.Any(), gomock.Any()).Return(nutsCrypto.TestPublicKey{
			PublicKey: publicKey,
		}, nil)
		m := NewManager(rootDID, tenantPath, keyStore, db)

		document, key, err := m.Create(audit.TestContext(), management.Create(MethodName))
		require.NoError(t, err)
		require.NotNil(t, document)
		require.NotNil(t, key)
		assert.Len(t, document.VerificationMethod, 1)
		assert.Len(t, document.Authentication, 1)
		assert.Len(t, document.CapabilityInvocation, 1)
		assert.Len(t, document.AssertionMethod, 1)
		assert.Len(t, document.KeyAgreement, 1)
	})
	t.Run("with root DID option", func(t *testing.T) {
		db := testDB(t)
		ctrl := gomock.NewController(t)
		keyStore := nutsCrypto.NewMockKeyStore(ctrl)
		keyStore.EXPECT().New(gomock.Any(), gomock.Any()).Return(nutsCrypto.TestPublicKey{
			PublicKey: publicKey,
		}, nil)
		m := NewManager(rootDID, tenantPath, keyStore, db)

		document, key, err := m.Create(audit.TestContext(), DefaultCreationOptions().With(RootDID()))
		require.NoError(t, err)
		require.NotNil(t, document)
		require.NotNil(t, key)
		assert.Equal(t, rootDID, document.ID)
	})
	t.Run("without options", func(t *testing.T) {
		db := testDB(t)
		ctrl := gomock.NewController(t)
		keyStore := nutsCrypto.NewMockKeyStore(ctrl)
		keyStore.EXPECT().New(gomock.Any(), gomock.Any()).Return(nutsCrypto.TestPublicKey{
			PublicKey: publicKey,
		}, nil)
		m := NewManager(rootDID, tenantPath, keyStore, db)

		document, key, err := m.Create(audit.TestContext(), DefaultCreationOptions())
		require.NoError(t, err)
		require.NotNil(t, document)
		require.NotNil(t, key)
		assert.True(t, strings.HasPrefix(document.ID.String(), "did:web:example.com:iam:"))
	})
	t.Run("with unknown option", func(t *testing.T) {
		db := testDB(t)
		ctrl := gomock.NewController(t)
		keyStore := nutsCrypto.NewMockKeyStore(ctrl)
		m := NewManager(rootDID, tenantPath, keyStore, db)

		_, _, err := m.Create(audit.TestContext(), DefaultCreationOptions().With(""))
		require.EqualError(t, err, "unknown option: string")
	})
	t.Run("already exists", func(t *testing.T) {
		db := testDB(t)
		ctrl := gomock.NewController(t)
		keyStore := nutsCrypto.NewMockKeyStore(ctrl)
		keyStore.EXPECT().New(gomock.Any(), gomock.Any()).Return(nutsCrypto.TestPublicKey{
			PublicKey: publicKey,
		}, nil)
		m := NewManager(rootDID, tenantPath, keyStore, db)
		opts := DefaultCreationOptions().With(RootDID())
		_, _, err := m.Create(audit.TestContext(), opts)
		require.NoError(t, err)

		_, _, err = m.Create(audit.TestContext(), opts)

		require.ErrorIs(t, err, management.ErrDIDAlreadyExists)
	})
}

func TestManager_IsOwner(t *testing.T) {
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())

	t.Run("not owned (empty store)", func(t *testing.T) {
		db := testDB(t)
		m := NewManager(rootDID, tenantPath, nutsCrypto.NewMemoryCryptoInstance(), db)

		owned, err := m.IsOwner(audit.TestContext(), subjectDID)
		require.NoError(t, err)
		assert.False(t, owned)
	})
	t.Run("not owned (other DID)", func(t *testing.T) {
		db := testDB(t)
		m := NewManager(rootDID, tenantPath, nutsCrypto.NewMemoryCryptoInstance(), db)
		_, _, err := m.Create(audit.TestContext(), DefaultCreationOptions())
		require.NoError(t, err)

		owned, err := m.IsOwner(audit.TestContext(), subjectDID)
		require.NoError(t, err)
		assert.False(t, owned)
	})
	t.Run("owned", func(t *testing.T) {
		db := testDB(t)
		m := NewManager(rootDID, tenantPath, nutsCrypto.NewMemoryCryptoInstance(), db)
		document, _, err := m.Create(audit.TestContext(), DefaultCreationOptions())
		require.NoError(t, err)

		owned, err := m.IsOwner(audit.TestContext(), document.ID)
		require.NoError(t, err)
		assert.True(t, owned)
	})
}

func TestManager_ListOwned(t *testing.T) {
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())

	t.Run("empty store", func(t *testing.T) {
		db := testDB(t)
		m := NewManager(rootDID, tenantPath, nutsCrypto.NewMemoryCryptoInstance(), db)

		dids, err := m.ListOwned(audit.TestContext())
		require.NoError(t, err)
		assert.Empty(t, dids)
	})
	t.Run("single DID", func(t *testing.T) {
		db := testDB(t)
		m := NewManager(rootDID, tenantPath, nutsCrypto.NewMemoryCryptoInstance(), db)
		document, _, err := m.Create(audit.TestContext(), DefaultCreationOptions())
		require.NoError(t, err)

		dids, err := m.ListOwned(audit.TestContext())
		require.NoError(t, err)
		assert.Equal(t, []did.DID{document.ID}, dids)
	})
	t.Run("multiple DIDs", func(t *testing.T) {
		db := testDB(t)
		m := NewManager(rootDID, tenantPath, nutsCrypto.NewMemoryCryptoInstance(), db)
		document1, _, err := m.Create(audit.TestContext(), DefaultCreationOptions())
		require.NoError(t, err)
		document2, _, err := m.Create(audit.TestContext(), DefaultCreationOptions())
		require.NoError(t, err)

		dids, err := m.ListOwned(audit.TestContext())
		require.NoError(t, err)
		assert.ElementsMatch(t, []did.DID{document1.ID, document2.ID}, dids)
	})
}

func TestManager_Resolve(t *testing.T) {
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())

	t.Run("not found", func(t *testing.T) {
		db := testDB(t)
		m := NewManager(rootDID, tenantPath, nutsCrypto.NewMemoryCryptoInstance(), db)

		document, _, err := m.Resolve(did.MustParseDID("did:web:example.com:1234"), nil)
		require.ErrorIs(t, err, resolver.ErrNotFound)
		assert.Nil(t, document)
	})
	t.Run("ok", func(t *testing.T) {
		db := testDB(t)
		m := NewManager(rootDID, tenantPath, nutsCrypto.NewMemoryCryptoInstance(), db)
		document, _, err := m.Create(audit.TestContext(), DefaultCreationOptions())
		require.NoError(t, err)
		expected, _ := document.MarshalJSON()

		resolvedDocument, _, err := m.Resolve(document.ID, nil)
		require.NoError(t, err)
		actual, _ := resolvedDocument.MarshalJSON()
		assert.JSONEq(t, string(expected), string(actual))
	})
}

func TestManager_Services(t *testing.T) {
	newManager := func(t *testing.T) *Manager {
		db := testDB(t)
		tx := db.Begin()
		didManager := sql.NewDIDManager(tx)
		didDocumentManager := sql.NewDIDDocumentManager(tx)
		m := NewManager(rootDID, tenantPath, nil, db)
		dids, err := didManager.Add("uuid", subjectDID)
		require.NoError(t, err)
		_, err = didDocumentManager.AddVersion(dids[0], nil, nil)
		require.NoError(t, err)
		tx.Commit()
		return m
	}

	t.Run("create", func(t *testing.T) {
		t.Run("with ID", func(t *testing.T) {
			m := newManager(t)

			expected := did.Service{
				ID:              ssi.MustParseURI(subjectDID.String() + "#api"),
				Type:            "API",
				ServiceEndpoint: "https://example.com/api",
			}
			actual, err := m.CreateService(ctx, subjectDID, expected)

			require.NoError(t, err)
			require.Equal(t, expected, *actual)
			didDocumentManager := sql.NewDIDDocumentManager(m.db)
			document, err := didDocumentManager.Latest(subjectDID)
			require.NoError(t, err)
			require.Len(t, document.Services, 1)
			assert.Equal(t, expected.ID.String(), document.Services[0].ID)

		})
		t.Run("random ID", func(t *testing.T) {
			m := newManager(t)

			input := did.Service{
				Type:            "API",
				ServiceEndpoint: "https://example.com/api",
			}

			actual, err := m.CreateService(ctx, subjectDID, input)

			require.NoError(t, err)
			assert.NotEqual(t, "", actual.ID.Fragment)
			didDocumentManager := sql.NewDIDDocumentManager(m.db)
			document, err := didDocumentManager.Latest(subjectDID)
			require.NoError(t, err)
			require.Len(t, document.Services, 1)
			assert.Equal(t, actual.ID.String(), document.Services[0].ID)
		})
	})
	t.Run("update", func(t *testing.T) {
		t.Run("ID not set", func(t *testing.T) {
			m := newManager(t)

			serviceID := ssi.MustParseURI(subjectDID.String() + "#api")
			input := did.Service{}
			expected := did.Service{
				ID: serviceID,
			}
			actual, err := m.UpdateService(ctx, subjectDID, serviceID, input)

			require.NoError(t, err)
			assert.Equal(t, expected, *actual)

			didDocumentManager := sql.NewDIDDocumentManager(m.db)
			document, err := didDocumentManager.Latest(subjectDID)
			require.NoError(t, err)
			require.Len(t, document.Services, 1)
			assert.Equal(t, expected.ID.String(), document.Services[0].ID)
		})
		t.Run("ID is set", func(t *testing.T) {
			m := newManager(t)

			serviceID := ssi.MustParseURI(subjectDID.String() + "#api")
			input := did.Service{
				ID: serviceID,
			}
			actual, err := m.UpdateService(ctx, subjectDID, serviceID, input)

			require.NoError(t, err)
			assert.Equal(t, input, *actual)
		})
	})
	t.Run("Delete", func(t *testing.T) {
		m := newManager(t)

		expected := did.Service{
			ID:              ssi.MustParseURI(subjectDID.String() + "#api"),
			Type:            "API",
			ServiceEndpoint: "https://example.com/api",
		}
		_, err := m.CreateService(ctx, subjectDID, expected)
		require.NoError(t, err)

		err = m.DeleteService(ctx, subjectDID, expected.ID)
		require.NoError(t, err)

		didDocumentManager := sql.NewDIDDocumentManager(m.db)
		document, err := didDocumentManager.Latest(subjectDID)
		require.NoError(t, err)
		assert.Len(t, document.Services, 0)
	})
}

func TestManager_Deactivate(t *testing.T) {
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())
	ctx := audit.TestContext()

	t.Run("not found", func(t *testing.T) {
		db := testDB(t)
		m := NewManager(rootDID, tenantPath, nutsCrypto.NewMemoryCryptoInstance(), db)

		err := m.Deactivate(ctx, subjectDID)
		require.ErrorIs(t, err, resolver.ErrNotFound)
	})
	t.Run("ok", func(t *testing.T) {
		db := testDB(t)
		cryptoInstance := nutsCrypto.NewMemoryCryptoInstance()
		m := NewManager(rootDID, tenantPath, cryptoInstance, db)
		document, _, err := m.Create(ctx, DefaultCreationOptions())
		require.NoError(t, err)

		// Sanity check for assertion after deactivation, check that we can find the private key
		exists, err := cryptoInstance.Exists(ctx, document.VerificationMethod[0].ID.String())
		require.NoError(t, err)
		require.True(t, exists)

		err = m.Deactivate(ctx, document.ID)
		require.NoError(t, err)

		_, _, err = m.Resolve(document.ID, nil)
		require.ErrorIs(t, err, resolver.ErrNotFound)

		// Make sure it cleans up private keys
		exists, err = cryptoInstance.Exists(ctx, document.VerificationMethod[0].ID.String())
		require.NoError(t, err)
		require.False(t, exists)
	})
	t.Run("unable to delete private key", func(t *testing.T) {
		db := testDB(t)
		cryptoInstance := nutsCrypto.NewMemoryCryptoInstance()
		m := NewManager(rootDID, tenantPath, cryptoInstance, db)
		document, _, err := m.Create(ctx, DefaultCreationOptions())
		require.NoError(t, err)

		exists, err := cryptoInstance.Exists(ctx, document.VerificationMethod[0].ID.String())
		require.NoError(t, err)
		require.True(t, exists)
		require.NoError(t, cryptoInstance.Delete(ctx, document.VerificationMethod[0].ID.String()))

		err = m.Deactivate(ctx, document.ID)

		require.EqualError(t, err, "did:web DID deleted, but could not remove one or more private keys\nverification method '"+document.VerificationMethod[0].ID.String()+"': private key not found")
	})
}
