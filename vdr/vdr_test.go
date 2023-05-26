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
	"context"
	"encoding/json"
	"errors"
	"github.com/nuts-foundation/nuts-node/audit"
	"testing"

	"github.com/golang/mock/gomock"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/nuts-foundation/nuts-node/vdr/didservice"
	"github.com/nuts-foundation/nuts-node/vdr/didstore"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const expectedPayloadType = "application/did+json"

// testCtx contains the controller and mocks needed fot testing the Manipulator
type vdrTestCtx struct {
	ctrl           *gomock.Controller
	vdr            VDR
	mockStore      *didstore.MockStore
	mockNetwork    *network.MockTransactions
	mockKeyStore   *crypto.MockKeyStore
	mockAmbassador *MockAmbassador
	ctx            context.Context
}

func newVDRTestCtx(t *testing.T) vdrTestCtx {
	t.Helper()
	ctrl := gomock.NewController(t)
	mockAmbassador := NewMockAmbassador(ctrl)
	mockStore := didstore.NewMockStore(ctrl)
	mockNetwork := network.NewMockTransactions(ctrl)
	mockKeyStore := crypto.NewMockKeyStore(ctrl)
	vdr := VDR{
		store:             mockStore,
		network:           mockNetwork,
		networkAmbassador: mockAmbassador,
		didDocCreator:     didservice.Creator{KeyStore: mockKeyStore},
		didDocResolver:    didservice.Resolver{Store: mockStore},
		keyStore:          mockKeyStore,
	}
	return vdrTestCtx{
		ctrl:           ctrl,
		vdr:            vdr,
		mockAmbassador: mockAmbassador,
		mockStore:      mockStore,
		mockNetwork:    mockNetwork,
		mockKeyStore:   mockKeyStore,
		ctx:            audit.TestContext(),
	}
}

func TestVDR_Update(t *testing.T) {
	id, _ := did.ParseDID("did:nuts:123")
	keyID, _ := did.ParseDIDURL("did:nuts:123#key-1")
	currentHash := hash.SHA256Sum([]byte("currentHash"))

	t.Run("ok", func(t *testing.T) {
		test := newVDRTestCtx(t)

		currentDIDDocument := did.Document{ID: *id, Controller: []did.DID{*id}}
		currentDIDDocument.AddCapabilityInvocation(&did.VerificationMethod{ID: *keyID})

		nextDIDDocument := didservice.CreateDocument()
		nextDIDDocument.ID = *id
		expectedResolverMetadata := &types.ResolveMetadata{
			AllowDeactivated: true,
		}
		resolvedMetadata := types.DocumentMetadata{
			SourceTransactions: []hash.SHA256Hash{currentHash},
		}
		test.mockStore.EXPECT().Resolve(*id, expectedResolverMetadata).Return(&currentDIDDocument, &resolvedMetadata, nil)
		test.mockStore.EXPECT().Resolve(*id, nil).Return(&currentDIDDocument, &resolvedMetadata, nil)
		test.mockKeyStore.EXPECT().Resolve(test.ctx, keyID.String()).Return(crypto.NewTestKey(keyID.String()), nil)
		test.mockNetwork.EXPECT().CreateTransaction(gomock.Any(), gomock.Any())

		err := test.vdr.Update(test.ctx, *id, nextDIDDocument)

		assert.NoError(t, err)
	})

	t.Run("error - validation failed", func(t *testing.T) {
		test := newVDRTestCtx(t)
		currentDIDDocument := didservice.CreateDocument()
		currentDIDDocument.ID = *id
		currentDIDDocument.Controller = []did.DID{currentDIDDocument.ID}

		nextDIDDocument := did.Document{}
		expectedResolverMetadata := &types.ResolveMetadata{
			AllowDeactivated: true,
		}
		resolvedMetadata := types.DocumentMetadata{}
		test.mockStore.EXPECT().Resolve(*id, expectedResolverMetadata).Return(&currentDIDDocument, &resolvedMetadata, nil)
		err := test.vdr.Update(test.ctx, *id, nextDIDDocument)
		assert.EqualError(t, err, "DID Document validation failed: invalid context")
	})

	t.Run("error - no controller for document", func(t *testing.T) {
		test := newVDRTestCtx(t)
		document := didservice.CreateDocument()
		document.ID = *id

		expectedResolverMetadata := &types.ResolveMetadata{
			AllowDeactivated: true,
		}
		resolvedMetadata := types.DocumentMetadata{}
		test.mockStore.EXPECT().Resolve(*id, expectedResolverMetadata).Return(&document, &resolvedMetadata, nil)
		err := test.vdr.Update(test.ctx, *id, document)
		assert.EqualError(t, err, "the DID document has been deactivated")
	})
	t.Run("error - could not resolve current document", func(t *testing.T) {
		test := newVDRTestCtx(t)
		nextDIDDocument := did.Document{}
		expectedResolverMetadata := &types.ResolveMetadata{
			AllowDeactivated: true,
		}
		test.mockStore.EXPECT().Resolve(*id, expectedResolverMetadata).Return(nil, nil, types.ErrNotFound)
		err := test.vdr.Update(test.ctx, *id, nextDIDDocument)
		assert.EqualError(t, err, "unable to find the DID document")
	})

	t.Run("error - document not managed by this node", func(t *testing.T) {
		test := newVDRTestCtx(t)
		nextDIDDocument := didservice.CreateDocument()
		nextDIDDocument.ID = *id
		currentDIDDocument := nextDIDDocument
		currentDIDDocument.AddCapabilityInvocation(&did.VerificationMethod{ID: *keyID})
		test.mockStore.EXPECT().Resolve(*id, gomock.Any()).Times(1).Return(&currentDIDDocument, &types.DocumentMetadata{}, nil)
		test.mockKeyStore.EXPECT().Resolve(test.ctx, keyID.String()).Return(nil, crypto.ErrPrivateKeyNotFound)

		err := test.vdr.Update(test.ctx, *id, nextDIDDocument)

		assert.Error(t, err)
		assert.EqualError(t, err, "DID document not managed by this node")
		assert.True(t, errors.Is(err, types.ErrDIDNotManagedByThisNode),
			"expected ErrDIDNotManagedByThisNode error when the document is not managed by this node")
	})
}
func TestVDR_Create(t *testing.T) {
	key := crypto.NewTestKey("did:nuts:123#key-1")
	id := did.MustParseDID("did:nuts:123")
	keyID, _ := did.ParseDIDURL(key.KID())
	controllerID := did.MustParseDID("did:nuts:456")
	vm, err := did.NewVerificationMethod(*keyID, ssi.JsonWebKey2020, did.DID{}, key.Public())
	require.NoError(t, err)
	controllerDocument := did.Document{ID: controllerID, Controller: []did.DID{}}
	DIDDocument := didservice.CreateDocument()
	DIDDocument.ID = id
	DIDDocument.AddCapabilityInvocation(vm)
	DIDDocument.AddAssertionMethod(vm)
	DIDDocument.AddKeyAgreement(vm)

	t.Run("ok", func(t *testing.T) {
		test := newVDRTestCtx(t)
		expectedPayload, _ := json.Marshal(DIDDocument)

		test.mockKeyStore.EXPECT().New(test.ctx, gomock.Any()).Return(key, nil)
		test.mockNetwork.EXPECT().CreateTransaction(test.ctx, network.TransactionTemplate(expectedPayloadType, expectedPayload, key).WithAttachKey().WithAdditionalPrevs([]hash.SHA256Hash{}))

		didDoc, key, err := test.vdr.Create(test.ctx, didservice.DefaultCreationOptions())

		assert.NoError(t, err)
		assert.NotNil(t, didDoc)
		assert.NotNil(t, key)
	})

	t.Run("ok with controllers in the options", func(t *testing.T) {
		test := newVDRTestCtx(t)
		copiedDocument := DIDDocument
		// given the selfControl option, both the controller and the DID should be added to the document
		copiedDocument.Controller = []did.DID{controllerID, id}
		expectedPayload, _ := json.Marshal(copiedDocument)
		refs := []hash.SHA256Hash{hash.EmptyHash()}
		creationOptions := types.DIDCreationOptions{
			Controllers: []did.DID{controllerID},
			KeyFlags:    types.AssertionMethodUsage | types.CapabilityInvocationUsage | types.KeyAgreementUsage,
			SelfControl: true,
		}
		test.mockKeyStore.EXPECT().New(test.ctx, gomock.Any()).Return(key, nil)
		test.mockStore.EXPECT().Resolve(controllerID, gomock.Any()).Return(&controllerDocument, &types.DocumentMetadata{SourceTransactions: refs}, nil)
		test.mockNetwork.EXPECT().CreateTransaction(test.ctx, network.TransactionTemplate(expectedPayloadType, expectedPayload, key).WithAttachKey().WithAdditionalPrevs(refs))

		didDoc, key, err := test.vdr.Create(test.ctx, creationOptions)

		assert.NoError(t, err)
		assert.NotNil(t, didDoc)
		assert.NotNil(t, key)
	})

	t.Run("error - unknown controllers", func(t *testing.T) {
		test := newVDRTestCtx(t)
		creationOptions := types.DIDCreationOptions{
			Controllers: []did.DID{controllerID},
			KeyFlags:    types.AssertionMethodUsage | types.CapabilityInvocationUsage | types.KeyAgreementUsage,
			SelfControl: true,
		}
		test.mockStore.EXPECT().Resolve(controllerID, gomock.Any()).Return(nil, nil, types.ErrNotFound)

		_, _, err := test.vdr.Create(test.ctx, creationOptions)

		assert.EqualError(t, err, "could not create DID document: could not resolve a controller: unable to find the DID document")
	})

	t.Run("error - doc creation", func(t *testing.T) {
		test := newVDRTestCtx(t)
		test.mockKeyStore.EXPECT().New(gomock.Any(), gomock.Any()).Return(nil, errors.New("b00m!"))

		_, _, err := test.vdr.Create(test.ctx, didservice.DefaultCreationOptions())

		assert.EqualError(t, err, "could not create DID document: b00m!")
	})

	t.Run("error - transaction failed", func(t *testing.T) {
		test := newVDRTestCtx(t)
		key := crypto.NewTestKey("did:nuts:123#key-1")
		test.mockKeyStore.EXPECT().New(gomock.Any(), gomock.Any()).Return(key, nil)
		test.mockNetwork.EXPECT().CreateTransaction(gomock.Any(), gomock.Any()).Return(nil, errors.New("b00m!"))

		_, _, err := test.vdr.Create(test.ctx, didservice.DefaultCreationOptions())

		assert.EqualError(t, err, "could not store DID document in network: b00m!")
	})
}

func TestNewVDR(t *testing.T) {
	cfg := Config{}
	vdr := NewVDR(cfg, nil, nil, nil, nil)
	assert.IsType(t, &VDR{}, vdr)
	assert.Equal(t, vdr.config, cfg)
}

func TestVDR_Migrate(t *testing.T) {
	t.Run("migrate on 0 document count", func(t *testing.T) {
		ctx := newVDRTestCtx(t)
		ctx.mockAmbassador.EXPECT().Start()
		ctx.mockStore.EXPECT().DocumentCount().Return(uint(0), nil)
		ctx.mockNetwork.EXPECT().Reprocess(context.Background(), "application/did+json").Return(nil, nil)

		err := ctx.vdr.Start()

		require.NoError(t, err)
	})
	t.Run("don't migrate on > 0 document count", func(t *testing.T) {
		ctx := newVDRTestCtx(t)
		ctx.mockAmbassador.EXPECT().Start()
		ctx.mockStore.EXPECT().DocumentCount().Return(uint(1), nil)

		err := ctx.vdr.Start()

		require.NoError(t, err)
	})
	t.Run("error on migration error", func(t *testing.T) {
		ctx := newVDRTestCtx(t)
		ctx.mockAmbassador.EXPECT().Start()
		testError := errors.New("test")
		ctx.mockStore.EXPECT().DocumentCount().Return(uint(0), testError)

		err := ctx.vdr.Start()

		assert.Equal(t, testError, err)
	})
}

func TestVDR_ConflictingDocuments(t *testing.T) {
	t.Run("diagnostics", func(t *testing.T) {
		t.Run("ok - no conflicts/no documents", func(t *testing.T) {
			s := didstore.NewTestStore(t)
			vdr := NewVDR(Config{}, nil, nil, s, nil)
			results := vdr.Diagnostics()

			require.Len(t, results, 2)
			assert.Equal(t, "map[owned_count:0 total_count:0]", results[0].String())
			assert.Equal(t, "0", results[1].String())
		})

		t.Run("ok - 1 conflict", func(t *testing.T) {
			s := didstore.NewTestStore(t)
			vdr := NewVDR(Config{}, nil, nil, s, nil)
			didDocument := did.Document{ID: TestDIDA}
			_ = s.Add(didDocument, didstore.TestTransaction(didDocument))
			_ = s.Add(didDocument, didstore.TestTransaction(didDocument))
			results := vdr.Diagnostics()

			require.Len(t, results, 2)
			assert.Equal(t, "map[owned_count:0 total_count:1]", results[0].String())
			assert.Equal(t, "1", results[1].String())
		})

		t.Run("ok - 1 owned conflict", func(t *testing.T) {
			s := didstore.NewTestStore(t)
			client := crypto.NewMemoryCryptoInstance()
			keyID := TestDIDA
			keyID.Fragment = "1"
			_, _ = client.New(audit.TestContext(), crypto.StringNamingFunc(keyID.String()))
			vdr := NewVDR(Config{}, client, nil, s, nil)
			didDocument := did.Document{ID: TestDIDA}

			didDocument.AddCapabilityInvocation(&did.VerificationMethod{ID: keyID})
			_ = s.Add(didDocument, didstore.TestTransaction(didDocument))
			_ = s.Add(didDocument, didstore.TestTransaction(didDocument))
			results := vdr.Diagnostics()

			require.Len(t, results, 2)
			assert.Equal(t, "map[owned_count:1 total_count:1]", results[0].String())
			assert.Equal(t, "1", results[1].String())
		})
	})
	t.Run("list", func(t *testing.T) {
		t.Run("ok - no conflicts", func(t *testing.T) {
			s := didstore.NewTestStore(t)
			vdr := NewVDR(Config{}, nil, nil, s, nil)
			docs, meta, err := vdr.ConflictedDocuments()

			require.NoError(t, err)
			assert.Len(t, docs, 0)
			assert.Len(t, meta, 0)
		})

		t.Run("ok - 1 conflict", func(t *testing.T) {
			s := didstore.NewTestStore(t)
			vdr := NewVDR(Config{}, nil, nil, s, nil)
			didDocument := did.Document{ID: TestDIDA}
			_ = s.Add(didDocument, didstore.TestTransaction(didDocument))
			_ = s.Add(didDocument, didstore.TestTransaction(didDocument))
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
		test := newVDRTestCtx(t)
		currentDIDDocument := did.Document{ID: *id, Controller: []did.DID{}}
		currentDIDDocument.AddCapabilityInvocation(&did.VerificationMethod{ID: *keyID})
		test.mockKeyStore.EXPECT().Resolve(test.ctx, keyID.String()).Return(crypto.NewTestKey(keyID.String()), nil)

		controller, key, err := test.vdr.resolveControllerWithKey(test.ctx, currentDIDDocument)

		require.NoError(t, err)
		assert.Equal(t, keyID.String(), key.KID())
		assert.Equal(t, *id, controller.ID)
	})

	t.Run("ok - key from 2nd controller", func(t *testing.T) {
		test := newVDRTestCtx(t)
		controller := did.Document{ID: *controllerId, Controller: []did.DID{}}
		currentDIDDocument := did.Document{ID: *id, Controller: []did.DID{*controllerId, *controllerId}}
		controller.AddCapabilityInvocation(&did.VerificationMethod{ID: *keyID})
		test.mockStore.EXPECT().Resolve(*controllerId, gomock.Any()).Return(&controller, nil, nil).Times(2)
		gomock.InOrder(
			test.mockKeyStore.EXPECT().Resolve(test.ctx, keyID.String()).Return(nil, crypto.ErrPrivateKeyNotFound),
			test.mockKeyStore.EXPECT().Resolve(test.ctx, keyID.String()).Return(crypto.NewTestKey(keyID.String()), nil),
		)

		_, key, err := test.vdr.resolveControllerWithKey(test.ctx, currentDIDDocument)

		require.NoError(t, err)
		assert.Equal(t, keyID.String(), key.KID())
		assert.Equal(t, *controllerId, controller.ID)
	})

	t.Run("error - resolving key", func(t *testing.T) {
		test := newVDRTestCtx(t)
		currentDIDDocument := did.Document{ID: *id, Controller: []did.DID{}}
		currentDIDDocument.AddCapabilityInvocation(&did.VerificationMethod{ID: *keyID})
		test.mockKeyStore.EXPECT().Resolve(test.ctx, keyID.String()).Return(nil, errors.New("b00m!"))

		_, _, err := test.vdr.resolveControllerWithKey(test.ctx, currentDIDDocument)

		assert.EqualError(t, err, "could not find capabilityInvocation key for updating the DID document: b00m!")
	})

	t.Run("error - no keys from any controller", func(t *testing.T) {
		test := newVDRTestCtx(t)
		controller := did.Document{ID: *controllerId, Controller: []did.DID{}}
		currentDIDDocument := did.Document{ID: *id, Controller: []did.DID{*controllerId, *controllerId}}
		controller.AddCapabilityInvocation(&did.VerificationMethod{ID: *keyID})
		test.mockStore.EXPECT().Resolve(*controllerId, gomock.Any()).Return(&controller, nil, nil).Times(2)
		test.mockKeyStore.EXPECT().Resolve(test.ctx, keyID.String()).Return(nil, crypto.ErrPrivateKeyNotFound).Times(2)

		_, _, err := test.vdr.resolveControllerWithKey(test.ctx, currentDIDDocument)

		assert.Equal(t, types.ErrDIDNotManagedByThisNode, err)
	})
}

func TestWithJSONLDContext(t *testing.T) {
	id, _ := did.ParseDID("did:nuts:123")
	expected := did.Document{ID: *id, Context: []ssi.URI{didservice.NutsDIDContextV1URI()}}

	t.Run("added if not present", func(t *testing.T) {
		document := did.Document{ID: *id}

		patched := withJSONLDContext(document, didservice.NutsDIDContextV1URI())

		assert.EqualValues(t, expected.Context, patched.Context)
	})

	t.Run("no changes if existing", func(t *testing.T) {
		patched := withJSONLDContext(expected, didservice.NutsDIDContextV1URI())

		assert.EqualValues(t, expected.Context, patched.Context)
	})
}
