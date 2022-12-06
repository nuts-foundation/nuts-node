/*
 * Copyright (C) 2021 Nuts community
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

package vdr

import (
	"encoding/json"
	"errors"
	"github.com/nuts-foundation/nuts-node/vdr/diddocuments/dochelper"
	"github.com/stretchr/testify/require"
	"testing"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/vdr/store"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"

	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/go-did/did"
	"github.com/stretchr/testify/assert"

	"github.com/nuts-foundation/nuts-node/network"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

const expectedPayloadType = "application/did+json"

// testCtx contains the controller and mocks needed fot testing the Manipulator
type vdrTestCtx struct {
	ctrl         *gomock.Controller
	vdr          VDR
	mockStore    *types.MockStore
	mockNetwork  *network.MockTransactions
	mockKeyStore *crypto.MockKeyStore
}

func newVDRTestCtx(t *testing.T) vdrTestCtx {
	t.Helper()
	ctrl := gomock.NewController(t)
	mockStore := types.NewMockStore(ctrl)
	mockNetwork := network.NewMockTransactions(ctrl)
	mockKeyStore := crypto.NewMockKeyStore(ctrl)
	t.Cleanup(func() {
		ctrl.Finish()
	})
	vdr := VDR{
		store:          mockStore,
		didDocResolver: dochelper.Resolver{Store: mockStore},
		network:        mockNetwork,
		keyStore:       mockKeyStore,
		didDocCreator:  dochelper.Creator{KeyStore: mockKeyStore},
	}
	return vdrTestCtx{
		ctrl:         ctrl,
		vdr:          vdr,
		mockStore:    mockStore,
		mockNetwork:  mockNetwork,
		mockKeyStore: mockKeyStore,
	}
}

func TestVDR_Update(t *testing.T) {
	id, _ := did.ParseDID("did:nuts:123")
	keyID, _ := did.ParseDIDURL("did:nuts:123#key-1")
	currentHash := hash.SHA256Sum([]byte("currentHash"))

	t.Run("ok", func(t *testing.T) {
		ctx := newVDRTestCtx(t)

		currentDIDDocument := did.Document{ID: *id, Controller: []did.DID{*id}}
		currentDIDDocument.AddCapabilityInvocation(&did.VerificationMethod{ID: *keyID})

		nextDIDDocument := dochelper.CreateDocument()
		nextDIDDocument.ID = *id
		expectedResolverMetadata := &types.ResolveMetadata{
			Hash:             &currentHash,
			AllowDeactivated: true,
		}
		resolvedMetadata := types.DocumentMetadata{
			SourceTransactions: []hash.SHA256Hash{currentHash},
		}
		ctx.mockStore.EXPECT().Resolve(*id, expectedResolverMetadata).Return(&currentDIDDocument, &resolvedMetadata, nil)
		ctx.mockStore.EXPECT().Resolve(*id, nil).Return(&currentDIDDocument, &resolvedMetadata, nil)
		ctx.mockKeyStore.EXPECT().Resolve(keyID.String()).Return(crypto.NewTestKey(keyID.String()), nil)
		ctx.mockNetwork.EXPECT().CreateTransaction(gomock.Any())

		err := ctx.vdr.Update(*id, currentHash, nextDIDDocument, nil)

		assert.NoError(t, err)
	})

	t.Run("ok - update without changes doesn't create a transaction", func(t *testing.T) {
		ctx := newVDRTestCtx(t)

		currentDIDDocument := did.Document{ID: *id, Controller: []did.DID{*id}}
		currentDIDDocument.AddCapabilityInvocation(&did.VerificationMethod{ID: *keyID})

		nextDIDDocument := dochelper.CreateDocument()
		nextDIDDocument.ID = *id

		payload, err := json.Marshal(nextDIDDocument)
		assert.NoError(t, err)

		payloadHash := hash.SHA256Sum(payload)

		expectedResolverMetadata := &types.ResolveMetadata{
			Hash:             &payloadHash,
			AllowDeactivated: true,
		}
		resolvedMetadata := types.DocumentMetadata{
			SourceTransactions: []hash.SHA256Hash{payloadHash},
		}

		ctx.mockStore.EXPECT().Resolve(*id, expectedResolverMetadata).Return(&currentDIDDocument, &resolvedMetadata, nil)

		err = ctx.vdr.Update(*id, payloadHash, nextDIDDocument, nil)
		assert.NoError(t, err)
	})

	t.Run("error - validation failed", func(t *testing.T) {
		ctx := newVDRTestCtx(t)
		currentDIDDocument := dochelper.CreateDocument()
		currentDIDDocument.ID = *id
		currentDIDDocument.Controller = []did.DID{currentDIDDocument.ID}

		nextDIDDocument := did.Document{}
		expectedResolverMetadata := &types.ResolveMetadata{
			Hash:             &currentHash,
			AllowDeactivated: true,
		}
		resolvedMetadata := types.DocumentMetadata{}
		ctx.mockStore.EXPECT().Resolve(*id, expectedResolverMetadata).Return(&currentDIDDocument, &resolvedMetadata, nil)
		err := ctx.vdr.Update(*id, currentHash, nextDIDDocument, nil)
		assert.EqualError(t, err, "DID Document validation failed: invalid context")
	})

	t.Run("error - no controller for document", func(t *testing.T) {
		ctx := newVDRTestCtx(t)
		document := dochelper.CreateDocument()
		document.ID = *id

		expectedResolverMetadata := &types.ResolveMetadata{
			Hash:             &currentHash,
			AllowDeactivated: true,
		}
		resolvedMetadata := types.DocumentMetadata{}
		ctx.mockStore.EXPECT().Resolve(*id, expectedResolverMetadata).Return(&document, &resolvedMetadata, nil)
		err := ctx.vdr.Update(*id, currentHash, document, nil)
		assert.EqualError(t, err, "the DID document has been deactivated")
	})
	t.Run("error - could not resolve current document", func(t *testing.T) {
		ctx := newVDRTestCtx(t)
		nextDIDDocument := did.Document{}
		expectedResolverMetadata := &types.ResolveMetadata{
			Hash:             &currentHash,
			AllowDeactivated: true,
		}
		ctx.mockStore.EXPECT().Resolve(*id, expectedResolverMetadata).Return(nil, nil, types.ErrNotFound)
		err := ctx.vdr.Update(*id, currentHash, nextDIDDocument, nil)
		assert.EqualError(t, err, "unable to find the DID document")
	})

	t.Run("error - document not managed by this node", func(t *testing.T) {
		ctx := newVDRTestCtx(t)
		nextDIDDocument := dochelper.CreateDocument()
		nextDIDDocument.ID = *id
		currentDIDDocument := nextDIDDocument
		currentDIDDocument.AddCapabilityInvocation(&did.VerificationMethod{ID: *keyID})
		ctx.mockStore.EXPECT().Resolve(*id, gomock.Any()).Times(1).Return(&currentDIDDocument, &types.DocumentMetadata{}, nil)
		ctx.mockKeyStore.EXPECT().Resolve(keyID.String()).Return(nil, crypto.ErrPrivateKeyNotFound)

		err := ctx.vdr.Update(*id, currentHash, nextDIDDocument, nil)

		assert.Error(t, err)
		assert.EqualError(t, err, "DID document not managed by this node")
		assert.True(t, errors.Is(err, types.ErrDIDNotManagedByThisNode),
			"expected ErrDIDNotManagedByThisNode error when the document is not managed by this node")
	})
}
func TestVDR_Create(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctx := newVDRTestCtx(t)
		key := crypto.NewTestKey("did:nuts:123#key-1")
		id, _ := did.ParseDID("did:nuts:123")
		keyID, _ := did.ParseDIDURL(key.KID())
		nextDIDDocument := dochelper.CreateDocument()
		nextDIDDocument.ID = *id
		vm, err := did.NewVerificationMethod(*keyID, ssi.JsonWebKey2020, did.DID{}, key.Public())
		require.NoError(t, err)
		nextDIDDocument.AddCapabilityInvocation(vm)
		nextDIDDocument.AddAssertionMethod(vm)
		nextDIDDocument.AddKeyAgreement(vm)
		expectedPayload, _ := json.Marshal(nextDIDDocument)

		ctx.mockKeyStore.EXPECT().New(gomock.Any()).Return(key, nil)
		ctx.mockNetwork.EXPECT().CreateTransaction(network.TransactionTemplate(expectedPayloadType, expectedPayload, key).WithAttachKey())

		didDoc, key, err := ctx.vdr.Create(dochelper.DefaultCreationOptions())

		assert.NoError(t, err)
		assert.NotNil(t, didDoc)
		assert.NotNil(t, key)
	})

	t.Run("error - doc creation", func(t *testing.T) {
		ctx := newVDRTestCtx(t)
		ctx.mockKeyStore.EXPECT().New(gomock.Any()).Return(nil, errors.New("b00m!"))

		_, _, err := ctx.vdr.Create(dochelper.DefaultCreationOptions())

		assert.EqualError(t, err, "could not create DID document: b00m!")
	})

	t.Run("error - transaction failed", func(t *testing.T) {
		ctx := newVDRTestCtx(t)
		key := crypto.NewTestKey("did:nuts:123#key-1")
		ctx.mockKeyStore.EXPECT().New(gomock.Any()).Return(key, nil)
		ctx.mockNetwork.EXPECT().CreateTransaction(gomock.Any()).Return(nil, errors.New("b00m!"))

		_, _, err := ctx.vdr.Create(dochelper.DefaultCreationOptions())

		assert.EqualError(t, err, "could not store DID document in network: b00m!")
	})
}

func TestNewVDR(t *testing.T) {
	cfg := Config{}
	vdr := NewVDR(cfg, nil, nil, nil, nil)
	assert.IsType(t, &VDR{}, vdr)
	assert.Equal(t, vdr.config, cfg)
}

func TestVDR_Configure(t *testing.T) {
	ctrl := gomock.NewController(t)
	tx := network.NewMockTransactions(ctrl)
	// Make sure configuring VDR subscribes to network
	tx.EXPECT().WithPersistency()
	tx.EXPECT().Subscribe("vdr", gomock.Any(), gomock.Any())
	cfg := Config{}
	vdr := NewVDR(cfg, nil, tx, nil, nil)
	err := vdr.Configure(*core.NewServerConfig())
	assert.NoError(t, err)
}

func TestVDR_ConflictingDocuments(t *testing.T) {
	t.Run("diagnostics", func(t *testing.T) {
		t.Run("ok - no conflicts", func(t *testing.T) {
			s := store.NewTestStore(t)
			vdr := NewVDR(Config{}, nil, nil, s, nil)
			results := vdr.Diagnostics()

			require.Len(t, results, 1)
			assert.Equal(t, "0", results[0].String())
		})

		t.Run("ok - 1 conflict", func(t *testing.T) {
			s := store.NewTestStore(t)
			vdr := NewVDR(Config{}, nil, nil, s, nil)
			doc := did.Document{ID: *TestDIDA}
			metadata := types.DocumentMetadata{SourceTransactions: []hash.SHA256Hash{hash.EmptyHash(), hash.EmptyHash()}}
			s.Write(doc, metadata)
			results := vdr.Diagnostics()

			require.Len(t, results, 1)
			assert.Equal(t, "1", results[0].String())
		})
	})
	t.Run("list", func(t *testing.T) {
		t.Run("ok - no conflicts", func(t *testing.T) {
			s := store.NewTestStore(t)
			vdr := NewVDR(Config{}, nil, nil, s, nil)
			docs, meta, err := vdr.ConflictedDocuments()

			require.NoError(t, err)
			assert.Len(t, docs, 0)
			assert.Len(t, meta, 0)
		})

		t.Run("ok - 1 conflict", func(t *testing.T) {
			s := store.NewTestStore(t)
			vdr := NewVDR(Config{}, nil, nil, s, nil)
			doc := did.Document{ID: *TestDIDA}
			metadata := types.DocumentMetadata{SourceTransactions: []hash.SHA256Hash{hash.EmptyHash(), hash.EmptyHash()}}
			s.Write(doc, metadata)
			docs, meta, err := vdr.ConflictedDocuments()

			require.NoError(t, err)
			assert.Len(t, docs, 1)
			assert.Len(t, meta, 1)
		})
	})
}

func TestVDR_resolveControllerKey(t *testing.T) {
	id, _ := did.ParseDID("did:nuts:123")
	controllerId, _ := did.ParseDID("did:nuts:1234")
	keyID, _ := did.ParseDIDURL("did:nuts:123#key-1")

	t.Run("ok - single doc", func(t *testing.T) {
		ctx := newVDRTestCtx(t)
		currentDIDDocument := did.Document{ID: *id, Controller: []did.DID{}}
		currentDIDDocument.AddCapabilityInvocation(&did.VerificationMethod{ID: *keyID})
		ctx.mockKeyStore.EXPECT().Resolve(keyID.String()).Return(crypto.NewTestKey(keyID.String()), nil)

		controller, key, err := ctx.vdr.resolveControllerWithKey(currentDIDDocument)

		require.NoError(t, err)
		assert.Equal(t, keyID.String(), key.KID())
		assert.Equal(t, *id, controller.ID)
	})

	t.Run("ok - key from 2nd controller", func(t *testing.T) {
		ctx := newVDRTestCtx(t)
		controller := did.Document{ID: *controllerId, Controller: []did.DID{}}
		currentDIDDocument := did.Document{ID: *id, Controller: []did.DID{*controllerId, *controllerId}}
		controller.AddCapabilityInvocation(&did.VerificationMethod{ID: *keyID})
		ctx.mockStore.EXPECT().Resolve(*controllerId, gomock.Any()).Return(&controller, nil, nil).Times(2)
		gomock.InOrder(
			ctx.mockKeyStore.EXPECT().Resolve(keyID.String()).Return(nil, crypto.ErrPrivateKeyNotFound),
			ctx.mockKeyStore.EXPECT().Resolve(keyID.String()).Return(crypto.NewTestKey(keyID.String()), nil),
		)

		_, key, err := ctx.vdr.resolveControllerWithKey(currentDIDDocument)

		require.NoError(t, err)
		assert.Equal(t, keyID.String(), key.KID())
		assert.Equal(t, *controllerId, controller.ID)
	})

	t.Run("error - resolving key", func(t *testing.T) {
		ctx := newVDRTestCtx(t)
		currentDIDDocument := did.Document{ID: *id, Controller: []did.DID{}}
		currentDIDDocument.AddCapabilityInvocation(&did.VerificationMethod{ID: *keyID})
		ctx.mockKeyStore.EXPECT().Resolve(keyID.String()).Return(nil, errors.New("b00m!"))

		_, _, err := ctx.vdr.resolveControllerWithKey(currentDIDDocument)

		assert.EqualError(t, err, "could not find capabilityInvocation key for updating the DID document: b00m!")
	})

	t.Run("error - no keys from any controller", func(t *testing.T) {
		ctx := newVDRTestCtx(t)
		controller := did.Document{ID: *controllerId, Controller: []did.DID{}}
		currentDIDDocument := did.Document{ID: *id, Controller: []did.DID{*controllerId, *controllerId}}
		controller.AddCapabilityInvocation(&did.VerificationMethod{ID: *keyID})
		ctx.mockStore.EXPECT().Resolve(*controllerId, gomock.Any()).Return(&controller, nil, nil).Times(2)
		ctx.mockKeyStore.EXPECT().Resolve(keyID.String()).Return(nil, crypto.ErrPrivateKeyNotFound).Times(2)

		_, _, err := ctx.vdr.resolveControllerWithKey(currentDIDDocument)

		assert.Equal(t, types.ErrDIDNotManagedByThisNode, err)
	})
}

func TestWithJSONLDContext(t *testing.T) {
	id, _ := did.ParseDID("did:nuts:123")
	expected := did.Document{ID: *id, Context: []ssi.URI{dochelper.NutsDIDContextV1URI()}}

	t.Run("added if not present", func(t *testing.T) {
		document := did.Document{ID: *id}

		patched := withJSONLDContext(document, dochelper.NutsDIDContextV1URI())

		assert.EqualValues(t, expected.Context, patched.Context)
	})

	t.Run("no changes if existing", func(t *testing.T) {
		patched := withJSONLDContext(expected, dochelper.NutsDIDContextV1URI())

		assert.EqualValues(t, expected.Context, patched.Context)
	})
}
