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

package didnuts

import (
	"context"
	"encoding/json"
	"errors"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/vdr/didnuts/didstore"
	"github.com/nuts-foundation/nuts-node/vdr/management"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"testing"
)

// managerTestContext contains the controller and mocks needed for testing the Manager
type managerTestContext struct {
	ctrl         *gomock.Controller
	mockDIDStore *didstore.MockStore
	mockNetwork  *network.MockTransactions
	mockResolver *resolver.MockDIDResolver
	mockKeyStore *mockKeyStore
	manager      *Manager
	audit        context.Context
}

func newManagerTestContext(t *testing.T) managerTestContext {
	t.Helper()

	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())
	db := storageEngine.GetSQLDatabase()

	ctrl := gomock.NewController(t)
	mockResolver := resolver.NewMockDIDResolver(ctrl)
	mockDIDStore := didstore.NewMockStore(ctrl)
	mockNetwork := network.NewMockTransactions(ctrl)
	keyStore := &mockKeyStore{}
	return managerTestContext{
		ctrl:         ctrl,
		mockDIDStore: mockDIDStore,
		mockNetwork:  mockNetwork,
		mockResolver: mockResolver,
		mockKeyStore: keyStore,
		manager:      NewManager(keyStore, mockNetwork, mockDIDStore, mockResolver, db),
		audit:        audit.TestContext(),
	}
}

func TestManager_Create(t *testing.T) {
	ctx := newManagerTestContext(t)
	ctx.mockNetwork.EXPECT().CreateTransaction(gomock.Any(), gomock.Any()).Do(func(_ context.Context, template network.Template) (dag.Transaction, error) {
		assert.Equal(t, DIDDocumentType, template.Type)
		assert.True(t, template.AttachKey)
		assert.Empty(t, template.AdditionalPrevs)
		assert.Empty(t, template.Participants)
		var didDocument did.Document
		_ = json.Unmarshal(template.Payload, &didDocument)
		assert.Len(t, didDocument.VerificationMethod, 1)
		assert.Len(t, didDocument.CapabilityInvocation, 1)
		assert.Len(t, didDocument.AssertionMethod, 1)
		assert.Len(t, didDocument.Authentication, 0)
		assert.Len(t, didDocument.KeyAgreement, 1)
		assert.Nil(t, didDocument.Service)
		return nil, nil
	})

	_, _, err := ctx.manager.Create(nil, management.EmptyCreationOptions())

	assert.NoError(t, err)
}

//func TestManager_Resolve(t *testing.T) {
//	_, _, err := Manager{}.Resolve(did.DID{}, nil)
//	assert.EqualError(t, err, "Resolve() is not supported for did:nuts")
//}

func TestManager_CreateService(t *testing.T) {
	_, err := Manager{}.CreateService(nil, did.DID{}, did.Service{})
	assert.EqualError(t, err, "CreateService() is not supported for did:nuts")
}

func TestManager_DeleteService(t *testing.T) {
	err := Manager{}.DeleteService(nil, did.DID{}, ssi.MustParseURI("https://example.com"))
	assert.EqualError(t, err, "DeleteService() is not supported for did:nuts")
}

func TestManager_UpdateService(t *testing.T) {
	_, err := Manager{}.UpdateService(nil, did.DID{}, ssi.MustParseURI("https://example.com"), did.Service{})
	assert.EqualError(t, err, "UpdateService() is not supported for did:nuts")
}

func TestManager_RemoveVerificationMethod(t *testing.T) {
	id123, _ := did.ParseDID("did:nuts:123")
	id123Method, _ := did.ParseDIDURL("did:nuts:123#method-1")
	publicKey := crypto.NewTestKey("did:nuts:123").Public()
	vm, _ := did.NewVerificationMethod(*id123Method, ssi.JsonWebKey2020, did.DID{}, publicKey)
	doc := &did.Document{ID: *id123}
	doc.AddCapabilityInvocation(vm)
	doc.AddCapabilityDelegation(vm)
	doc.AddAssertionMethod(vm)
	doc.AddAuthenticationMethod(vm)
	doc.AddKeyAgreement(vm)
	assert.Equal(t, vm, doc.CapabilityInvocation[0].VerificationMethod)
	assert.Equal(t, vm, doc.VerificationMethod[0])

	t.Run("ok", func(t *testing.T) {
		ctx := newManagerTestContext(t)
		doc1 := *doc
		doc2 := *doc
		ctx.mockResolver.EXPECT().Resolve(*id123, &resolver.ResolveMetadata{AllowDeactivated: true}).Return(&doc1, &resolver.DocumentMetadata{}, nil)
		ctx.mockResolver.EXPECT().Resolve(*id123, nil).Return(&doc2, &resolver.DocumentMetadata{}, nil)
		ctx.mockDIDStore.EXPECT().Resolve(*id123, &resolver.ResolveMetadata{AllowDeactivated: true}).Return(&doc2, &resolver.DocumentMetadata{}, nil)
		ctx.mockNetwork.EXPECT().CreateTransaction(gomock.Any(), gomock.Any()).Do(func(_ context.Context, template network.Template) (dag.Transaction, error) {
			var didDocument did.Document
			_ = json.Unmarshal(template.Payload, &didDocument)
			assert.Empty(t, didDocument.VerificationMethod)
			return nil, nil
		})

		err := ctx.manager.RemoveVerificationMethod(ctx.audit, *id123, *id123Method)
		require.NoError(t, err)
	})

	t.Run("ok - verificationMethod is not part of the document", func(t *testing.T) {
		ctx := newManagerTestContext(t)
		ctx.mockResolver.EXPECT().Resolve(*id123, &resolver.ResolveMetadata{AllowDeactivated: true}).Return(&did.Document{ID: *id123}, &resolver.DocumentMetadata{}, nil)

		err := ctx.manager.RemoveVerificationMethod(ctx.audit, *id123, *id123Method)

		assert.NoError(t, err)
	})

	t.Run("error - document is deactivated", func(t *testing.T) {
		ctx := newManagerTestContext(t)
		doc1 := *doc
		doc2 := *doc
		ctx.mockResolver.EXPECT().Resolve(*id123, &resolver.ResolveMetadata{AllowDeactivated: true}).Return(&doc1, &resolver.DocumentMetadata{Deactivated: true}, nil)
		ctx.mockDIDStore.EXPECT().Resolve(*id123, &resolver.ResolveMetadata{AllowDeactivated: true}).Return(&doc2, &resolver.DocumentMetadata{Deactivated: true}, nil)

		err := ctx.manager.RemoveVerificationMethod(ctx.audit, *id123, *id123Method)
		assert.True(t, errors.Is(err, resolver.ErrDeactivated))
		assert.True(t, errors.Is(err, resolver.ErrDeactivated))
	})
}

func TestManager_CreateNewAuthenticationMethodForDID(t *testing.T) {
	id123, _ := did.ParseDID("did:nuts:123")

	kc := &mockKeyStore{}

	t.Run("ok", func(t *testing.T) {
		// Prepare a document with an authenticationMethod:
		document := &did.Document{ID: *id123}
		method, err := CreateNewVerificationMethodForDID(audit.TestContext(), document.ID, kc)
		require.NoError(t, err)
		document.AddCapabilityInvocation(method)

		assert.NotNil(t, method)
		assert.Len(t, document.CapabilityInvocation, 1)
		assert.Equal(t, method.ID.String(), document.CapabilityInvocation[0].ID.String())
		assert.Equal(t, kc.key.KID(), document.CapabilityInvocation[0].ID.String())
	})
}

func TestManipulator_AddKey(t *testing.T) {
	id, _ := did.ParseDID("did:nuts:123")
	keyID, _ := did.ParseDIDURL("did:nuts:123#key-1")

	t.Run("ok - add a new key", func(t *testing.T) {
		ctx := newManagerTestContext(t)

		currentDIDDocument := did.Document{ID: *id, Controller: []did.DID{*id}}
		ctx.mockResolver.EXPECT().Resolve(*id, &resolver.ResolveMetadata{AllowDeactivated: true}).Return(&currentDIDDocument, &resolver.DocumentMetadata{}, nil)
		ctx.mockDIDStore.EXPECT().Resolve(*id, &resolver.ResolveMetadata{AllowDeactivated: true}).Return(&currentDIDDocument, &resolver.DocumentMetadata{}, nil)
		ctx.mockResolver.EXPECT().Resolve(*id, nil).Return(&currentDIDDocument, &resolver.DocumentMetadata{}, nil)
		ctx.mockNetwork.EXPECT().CreateTransaction(gomock.Any(), gomock.Any()).Do(func(_ context.Context, template network.Template) (dag.Transaction, error) {
			var didDocument did.Document
			_ = json.Unmarshal(template.Payload, &didDocument)
			assert.Len(t, didDocument.VerificationMethod, 1)
			assert.Len(t, didDocument.CapabilityInvocation, 1)
			return nil, nil
		})

		key, err := ctx.manager.AddVerificationMethod(ctx.audit, *id, management.CapabilityInvocationUsage)
		require.NoError(t, err)
		assert.NotNil(t, key)
		assert.Equal(t, key.Controller, *id,
			"expected method to have DID as controller")
	})

	t.Run("error - didStore throws an error", func(t *testing.T) {
		ctx := newManagerTestContext(t)

		currentDIDDocument := did.Document{ID: *id, Controller: []did.DID{*id}}
		currentDIDDocument.AddCapabilityInvocation(&did.VerificationMethod{ID: *keyID})
		ctx.mockResolver.EXPECT().Resolve(*id, &resolver.ResolveMetadata{AllowDeactivated: true}).Return(&currentDIDDocument, &resolver.DocumentMetadata{}, nil)
		ctx.mockDIDStore.EXPECT().Resolve(*id, &resolver.ResolveMetadata{AllowDeactivated: true}).Return(nil, nil, resolver.ErrNotFound)

		key, err := ctx.manager.AddVerificationMethod(ctx.audit, *id, 0)
		assert.ErrorIs(t, err, resolver.ErrNotFound)
		assert.Nil(t, key)
	})

	t.Run("error - did is deactivated", func(t *testing.T) {
		ctx := newManagerTestContext(t)

		currentDIDDocument := did.Document{ID: *id, Controller: []did.DID{*id}}
		ctx.mockResolver.EXPECT().Resolve(*id, &resolver.ResolveMetadata{AllowDeactivated: true}).Return(&currentDIDDocument, &resolver.DocumentMetadata{Deactivated: true}, nil)

		key, err := ctx.manager.AddVerificationMethod(nil, *id, 0)

		assert.ErrorIs(t, err, resolver.ErrDeactivated)
		assert.Nil(t, key)
	})
}
