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
	"encoding/json"
	"github.com/lestrrat-go/jwx/v2/jwk"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/audit"
	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/vdr/management"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
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
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())

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
		resetStore(t, storageEngine.GetSQLDatabase())
		ctrl := gomock.NewController(t)
		keyStore := nutsCrypto.NewMockKeyStore(ctrl)
		keyStore.EXPECT().New(gomock.Any(), gomock.Any()).Return(nutsCrypto.TestPublicKey{
			PublicKey: publicKey,
		}, nil)
		m := NewManager(rootDID, tenantPath, keyStore, storageEngine.GetSQLDatabase())

		document, key, err := m.Create(audit.TestContext(), management.Create(MethodName).With(Tenant("e9d4b80d-59eb-4f35-ada8-c75f6e14bbc4")))
		require.NoError(t, err)
		require.NotNil(t, document)
		require.NotNil(t, key)

		const expected = `
{
  "@context": [
    "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json",
    "https://www.w3.org/ns/did/v1"
  ],
  "assertionMethod": [
    "did:web:example.com:iam:e9d4b80d-59eb-4f35-ada8-c75f6e14bbc4#0"
  ],
  "authentication": [
    "did:web:example.com:iam:e9d4b80d-59eb-4f35-ada8-c75f6e14bbc4#0"
  ],
  "capabilityDelegation": [
    "did:web:example.com:iam:e9d4b80d-59eb-4f35-ada8-c75f6e14bbc4#0"
  ],
  "capabilityInvocation": [
    "did:web:example.com:iam:e9d4b80d-59eb-4f35-ada8-c75f6e14bbc4#0"
  ],
  "id": "did:web:example.com:iam:e9d4b80d-59eb-4f35-ada8-c75f6e14bbc4",
  "keyAgreement": [
    "did:web:example.com:iam:e9d4b80d-59eb-4f35-ada8-c75f6e14bbc4#0"
  ],
  "verificationMethod": [
    {
      "controller": "did:web:example.com:iam:e9d4b80d-59eb-4f35-ada8-c75f6e14bbc4",
      "id": "did:web:example.com:iam:e9d4b80d-59eb-4f35-ada8-c75f6e14bbc4#0",
      "publicKeyJwk": {
        "crv": "P-256",
        "kty": "EC",
        "x": "4VT-BXoTel3lvlwJRFFgN0XhWeSdziIzgHqE_J-o42k",
        "y": "yXwrpCkfKm44IcAI4INk_flMwFULonJeo595_g-dwwE"
      },
      "type": "JsonWebKey2020"
    }
  ]
}`
		actual, _ := json.Marshal(document)
		assert.JSONEq(t, expected, string(actual))
	})
	t.Run("with Tenant option", func(t *testing.T) {
		resetStore(t, storageEngine.GetSQLDatabase())
		ctrl := gomock.NewController(t)
		keyStore := nutsCrypto.NewMockKeyStore(ctrl)
		keyStore.EXPECT().New(gomock.Any(), gomock.Any()).Return(nutsCrypto.TestPublicKey{
			PublicKey: publicKey,
		}, nil)
		m := NewManager(rootDID, tenantPath, keyStore, storageEngine.GetSQLDatabase())

		document, key, err := m.Create(audit.TestContext(), DefaultCreationOptions().With(Tenant("test")))
		require.NoError(t, err)
		require.NotNil(t, document)
		require.NotNil(t, key)
		assert.True(t, strings.HasSuffix(document.ID.String(), ":test"))
	})
	t.Run("with root DID option", func(t *testing.T) {
		resetStore(t, storageEngine.GetSQLDatabase())
		ctrl := gomock.NewController(t)
		keyStore := nutsCrypto.NewMockKeyStore(ctrl)
		keyStore.EXPECT().New(gomock.Any(), gomock.Any()).Return(nutsCrypto.TestPublicKey{
			PublicKey: publicKey,
		}, nil)
		m := NewManager(rootDID, tenantPath, keyStore, storageEngine.GetSQLDatabase())
		expected := did.MustParseDID("did:web:example.com")

		document, key, err := m.Create(audit.TestContext(), DefaultCreationOptions().With(DID(expected)))
		require.NoError(t, err)
		require.NotNil(t, document)
		require.NotNil(t, key)
		assert.Equal(t, expected, document.ID)
	})
	t.Run("with DID (containing optional path) option", func(t *testing.T) {
		resetStore(t, storageEngine.GetSQLDatabase())
		ctrl := gomock.NewController(t)
		keyStore := nutsCrypto.NewMockKeyStore(ctrl)
		keyStore.EXPECT().New(gomock.Any(), gomock.Any()).Return(nutsCrypto.TestPublicKey{
			PublicKey: publicKey,
		}, nil)
		m := NewManager(rootDID, tenantPath, keyStore, storageEngine.GetSQLDatabase())
		expected := did.MustParseDID("did:web:example.com:iam:1234")

		document, key, err := m.Create(audit.TestContext(), DefaultCreationOptions().With(DID(expected)))
		require.NoError(t, err)
		require.NotNil(t, document)
		require.NotNil(t, key)
		assert.Equal(t, expected, document.ID)
	})
	t.Run("without options", func(t *testing.T) {
		resetStore(t, storageEngine.GetSQLDatabase())
		ctrl := gomock.NewController(t)
		keyStore := nutsCrypto.NewMockKeyStore(ctrl)
		keyStore.EXPECT().New(gomock.Any(), gomock.Any()).Return(nutsCrypto.TestPublicKey{
			PublicKey: publicKey,
		}, nil)
		m := NewManager(rootDID, tenantPath, keyStore, storageEngine.GetSQLDatabase())

		document, key, err := m.Create(audit.TestContext(), DefaultCreationOptions())
		require.NoError(t, err)
		require.NotNil(t, document)
		require.NotNil(t, key)
		assert.True(t, strings.HasPrefix(document.ID.String(), "did:web:example.com:iam:"))
	})
	t.Run("with invalid root DID (does not match with configured root DID)", func(t *testing.T) {
		resetStore(t, storageEngine.GetSQLDatabase())
		m := NewManager(rootDID, tenantPath, nil, storageEngine.GetSQLDatabase())
		expected := did.MustParseDID("did:web:example.org")

		_, _, err := m.Create(audit.TestContext(), DefaultCreationOptions().With(DID(expected)))
		require.EqualError(t, err, "invalid DID, does not match configured base URL, translated to DID: "+rootDID.String())
	})
	t.Run("with invalid tenant (contains subpath) DID option", func(t *testing.T) {
		resetStore(t, storageEngine.GetSQLDatabase())
		m := NewManager(rootDID, tenantPath, nil, storageEngine.GetSQLDatabase())
		expected := did.MustParseDID("did:web:example.com:iam:invalid:1234")

		_, _, err := m.Create(audit.TestContext(), DefaultCreationOptions().With(DID(expected)))
		require.EqualError(t, err, "invalid path in did:web DID, it must follow the pattern 'did:web:<host>:iam:<tenant>'")
	})
	t.Run("with invalid tenant (path does not start with /iam) DID option", func(t *testing.T) {
		resetStore(t, storageEngine.GetSQLDatabase())
		m := NewManager(rootDID, tenantPath, nil, storageEngine.GetSQLDatabase())
		expected := did.MustParseDID("did:web:example.com:iam:1234:invalid")

		_, _, err := m.Create(audit.TestContext(), DefaultCreationOptions().With(DID(expected)))
		require.EqualError(t, err, "invalid path in did:web DID, it must follow the pattern 'did:web:<host>:iam:<tenant>'")
	})
	t.Run("with empty tenant DID option", func(t *testing.T) {
		resetStore(t, storageEngine.GetSQLDatabase())
		m := NewManager(rootDID, tenantPath, nil, storageEngine.GetSQLDatabase())
		expected := did.MustParseDID("did:web:example.com:iam:")

		_, _, err := m.Create(audit.TestContext(), DefaultCreationOptions().With(DID(expected)))
		require.EqualError(t, err, "invalid path in did:web DID, it must follow the pattern 'did:web:<host>:iam:<tenant>'")
	})
	t.Run("with both DID and tenant options", func(t *testing.T) {
		resetStore(t, storageEngine.GetSQLDatabase())
		ctrl := gomock.NewController(t)
		keyStore := nutsCrypto.NewMockKeyStore(ctrl)
		m := NewManager(rootDID, tenantPath, keyStore, storageEngine.GetSQLDatabase())

		_, _, err := m.Create(audit.TestContext(), DefaultCreationOptions().With(DID(subjectDID)).With(Tenant("test")))
		require.EqualError(t, err, "multiple DID options provided")
	})
	t.Run("with unknown option", func(t *testing.T) {
		resetStore(t, storageEngine.GetSQLDatabase())
		ctrl := gomock.NewController(t)
		keyStore := nutsCrypto.NewMockKeyStore(ctrl)
		m := NewManager(rootDID, tenantPath, keyStore, storageEngine.GetSQLDatabase())

		_, _, err := m.Create(audit.TestContext(), DefaultCreationOptions().With(""))
		require.EqualError(t, err, "unknown option: string")
	})
	t.Run("already exists", func(t *testing.T) {
		resetStore(t, storageEngine.GetSQLDatabase())
		ctrl := gomock.NewController(t)
		keyStore := nutsCrypto.NewMockKeyStore(ctrl)
		keyStore.EXPECT().New(gomock.Any(), gomock.Any()).Return(nutsCrypto.TestPublicKey{
			PublicKey: publicKey,
		}, nil)
		m := NewManager(rootDID, tenantPath, keyStore, storageEngine.GetSQLDatabase())
		opts := DefaultCreationOptions().With(Tenant("test"))
		_, _, err := m.Create(audit.TestContext(), opts)
		require.NoError(t, err)

		_, _, err = m.Create(audit.TestContext(), opts)

		require.ErrorIs(t, err, management.ErrDIDAlreadyExists)
	})
	t.Run("with invalid tenant", func(t *testing.T) {
		resetStore(t, storageEngine.GetSQLDatabase())
		ctrl := gomock.NewController(t)
		keyStore := nutsCrypto.NewMockKeyStore(ctrl)
		m := NewManager(rootDID, tenantPath, keyStore, storageEngine.GetSQLDatabase())

		document, key, err := m.Create(audit.TestContext(), DefaultCreationOptions().With(Tenant("spaces in tenant")))

		require.EqualError(t, err, "invalid new DID: did:web:example.com:iam:spaces in tenant: invalid DID")
		require.Nil(t, document)
		require.Nil(t, key)
	})
}

func TestManager_IsOwner(t *testing.T) {
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())

	t.Run("not owned (empty store)", func(t *testing.T) {
		resetStore(t, storageEngine.GetSQLDatabase())
		m := NewManager(rootDID, tenantPath, nutsCrypto.NewMemoryCryptoInstance(), storageEngine.GetSQLDatabase())

		owned, err := m.IsOwner(audit.TestContext(), subjectDID)
		require.NoError(t, err)
		assert.False(t, owned)
	})
	t.Run("not owned (other DID)", func(t *testing.T) {
		resetStore(t, storageEngine.GetSQLDatabase())
		m := NewManager(rootDID, tenantPath, nutsCrypto.NewMemoryCryptoInstance(), storageEngine.GetSQLDatabase())
		_, _, err := m.Create(audit.TestContext(), DefaultCreationOptions())
		require.NoError(t, err)

		owned, err := m.IsOwner(audit.TestContext(), subjectDID)
		require.NoError(t, err)
		assert.False(t, owned)
	})
	t.Run("owned", func(t *testing.T) {
		resetStore(t, storageEngine.GetSQLDatabase())
		m := NewManager(rootDID, tenantPath, nutsCrypto.NewMemoryCryptoInstance(), storageEngine.GetSQLDatabase())
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
		resetStore(t, storageEngine.GetSQLDatabase())
		m := NewManager(rootDID, tenantPath, nutsCrypto.NewMemoryCryptoInstance(), storageEngine.GetSQLDatabase())

		dids, err := m.ListOwned(audit.TestContext())
		require.NoError(t, err)
		assert.Empty(t, dids)
	})
	t.Run("single DID", func(t *testing.T) {
		resetStore(t, storageEngine.GetSQLDatabase())
		m := NewManager(rootDID, tenantPath, nutsCrypto.NewMemoryCryptoInstance(), storageEngine.GetSQLDatabase())
		document, _, err := m.Create(audit.TestContext(), DefaultCreationOptions())
		require.NoError(t, err)

		dids, err := m.ListOwned(audit.TestContext())
		require.NoError(t, err)
		assert.Equal(t, []did.DID{document.ID}, dids)
	})
	t.Run("multiple DIDs", func(t *testing.T) {
		resetStore(t, storageEngine.GetSQLDatabase())
		m := NewManager(rootDID, tenantPath, nutsCrypto.NewMemoryCryptoInstance(), storageEngine.GetSQLDatabase())
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
		resetStore(t, storageEngine.GetSQLDatabase())
		m := NewManager(rootDID, tenantPath, nutsCrypto.NewMemoryCryptoInstance(), storageEngine.GetSQLDatabase())

		document, _, err := m.Resolve(did.MustParseDID("did:web:example.com:1234"), nil)
		require.ErrorIs(t, err, resolver.ErrNotFound)
		assert.Nil(t, document)
	})
	t.Run("ok", func(t *testing.T) {
		resetStore(t, storageEngine.GetSQLDatabase())
		m := NewManager(rootDID, tenantPath, nutsCrypto.NewMemoryCryptoInstance(), storageEngine.GetSQLDatabase())
		document, _, err := m.Create(audit.TestContext(), DefaultCreationOptions())
		require.NoError(t, err)
		expected, _ := document.MarshalJSON()

		resolvedDocument, _, err := m.Resolve(document.ID, nil)
		require.NoError(t, err)
		actual, _ := resolvedDocument.MarshalJSON()
		assert.JSONEq(t, string(expected), string(actual))
	})
}

func TestManager_CreateService(t *testing.T) {
	t.Run("with ID", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		store := NewMockstore(ctrl)
		m := NewManager(rootDID, tenantPath, nil, nil)
		m.store = store

		expected := did.Service{
			ID:              ssi.MustParseURI(subjectDID.String() + "#api"),
			Type:            "API",
			ServiceEndpoint: "https://example.com/api",
		}
		store.EXPECT().createService(subjectDID, expected).Return(nil)

		actual, err := m.CreateService(ctx, subjectDID, expected)

		require.NoError(t, err)
		require.Equal(t, expected, *actual)
	})
	t.Run("random ID", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		store := NewMockstore(ctrl)
		m := NewManager(rootDID, tenantPath, nil, nil)
		m.store = store

		input := did.Service{
			Type:            "API",
			ServiceEndpoint: "https://example.com/api",
		}
		var storedService did.Service
		store.EXPECT().createService(subjectDID, gomock.Any()).DoAndReturn(func(_ did.DID, service did.Service) error {
			storedService = service
			assert.NotEmpty(t, service.ID.Fragment)
			assert.True(t, strings.HasPrefix(service.ID.String(), subjectDID.String()))
			return nil
		})

		actual, err := m.CreateService(ctx, subjectDID, input)

		require.NoError(t, err)
		assert.Equal(t, storedService, *actual)
	})
}

func TestManager_UpdateService(t *testing.T) {
	t.Run("ID not set", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		store := NewMockstore(ctrl)
		m := NewManager(rootDID, tenantPath, nil, nil)
		m.store = store

		serviceID := ssi.MustParseURI(subjectDID.String() + "#api")
		input := did.Service{}
		expected := did.Service{
			ID: serviceID,
		}
		var storedService did.Service
		store.EXPECT().updateService(subjectDID, serviceID, gomock.Any()).DoAndReturn(func(_ did.DID, _ ssi.URI, service did.Service) error {
			storedService = service
			return nil
		})

		actual, err := m.UpdateService(ctx, subjectDID, serviceID, input)

		require.NoError(t, err)
		assert.Equal(t, expected, *actual)
		assert.Equal(t, storedService, *actual)
	})
	t.Run("ID is set", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		store := NewMockstore(ctrl)
		m := NewManager(rootDID, tenantPath, nil, nil)
		m.store = store

		serviceID := ssi.MustParseURI(subjectDID.String() + "#api")
		input := did.Service{
			ID: serviceID,
		}
		var storedService did.Service
		store.EXPECT().updateService(subjectDID, serviceID, gomock.Any()).DoAndReturn(func(_ did.DID, _ ssi.URI, service did.Service) error {
			storedService = service
			return nil
		})

		actual, err := m.UpdateService(ctx, subjectDID, serviceID, input)

		require.NoError(t, err)
		assert.Equal(t, input, *actual)
		assert.Equal(t, storedService, *actual)
	})
}

func TestManager_DeleteService(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := NewMockstore(ctrl)
	m := NewManager(rootDID, tenantPath, nil, nil)
	m.store = store

	serviceID := ssi.MustParseURI(subjectDID.String() + "#api")
	store.EXPECT().deleteService(subjectDID, serviceID).Return(nil)

	err := m.DeleteService(ctx, subjectDID, serviceID)

	require.NoError(t, err)
}

func TestManager_Deactivate(t *testing.T) {
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())
	ctx := audit.TestContext()

	t.Run("not found", func(t *testing.T) {
		resetStore(t, storageEngine.GetSQLDatabase())
		m := NewManager(rootDID, tenantPath, nutsCrypto.NewMemoryCryptoInstance(), storageEngine.GetSQLDatabase())

		err := m.Deactivate(ctx, subjectDID)
		require.ErrorIs(t, err, resolver.ErrNotFound)
	})
	t.Run("ok", func(t *testing.T) {
		resetStore(t, storageEngine.GetSQLDatabase())
		cryptoInstance := nutsCrypto.NewMemoryCryptoInstance()
		m := NewManager(rootDID, tenantPath, cryptoInstance, storageEngine.GetSQLDatabase())
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
		resetStore(t, storageEngine.GetSQLDatabase())
		cryptoInstance := nutsCrypto.NewMemoryCryptoInstance()
		m := NewManager(rootDID, tenantPath, cryptoInstance, storageEngine.GetSQLDatabase())
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
