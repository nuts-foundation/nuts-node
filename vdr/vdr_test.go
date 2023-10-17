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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vdr/didnuts"
	"github.com/nuts-foundation/nuts-node/vdr/didnuts/didstore"
	"github.com/nuts-foundation/nuts-node/vdr/management"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

const expectedPayloadType = "application/did+json"

// testCtx contains the controller and mocks needed fot testing the Manipulator
type vdrTestCtx struct {
	ctrl           *gomock.Controller
	vdr            Module
	mockStore      *didstore.MockStore
	mockNetwork    *network.MockTransactions
	mockKeyStore   *crypto.MockKeyStore
	mockAmbassador *didnuts.MockAmbassador
	ctx            context.Context
	mockOwner      *management.MockDocumentOwner
}

func newVDRTestCtx(t *testing.T) vdrTestCtx {
	t.Helper()
	ctrl := gomock.NewController(t)
	mockAmbassador := didnuts.NewMockAmbassador(ctrl)
	mockStore := didstore.NewMockStore(ctrl)
	mockNetwork := network.NewMockTransactions(ctrl)
	mockKeyStore := crypto.NewMockKeyStore(ctrl)
	mockDocumentOwner := management.NewMockDocumentOwner(ctrl)
	resolverRouter := &resolver.DIDResolverRouter{}
	vdr := Module{
		store:             mockStore,
		network:           mockNetwork,
		networkAmbassador: mockAmbassador,
		didDocCreator:     didnuts.Creator{KeyStore: mockKeyStore},
		didResolver:       resolverRouter,
		documentOwner:     mockDocumentOwner,
		keyStore:          mockKeyStore,
	}
	resolverRouter.Register(didnuts.MethodName, &didnuts.Resolver{Store: mockStore})
	return vdrTestCtx{
		ctrl:           ctrl,
		vdr:            vdr,
		mockAmbassador: mockAmbassador,
		mockStore:      mockStore,
		mockNetwork:    mockNetwork,
		mockKeyStore:   mockKeyStore,
		mockOwner:      mockDocumentOwner,
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

		nextDIDDocument := didnuts.CreateDocument()
		nextDIDDocument.ID = *id
		expectedResolverMetadata := &resolver.ResolveMetadata{
			AllowDeactivated: true,
		}
		resolvedMetadata := resolver.DocumentMetadata{
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
		currentDIDDocument := didnuts.CreateDocument()
		currentDIDDocument.ID = *id
		currentDIDDocument.Controller = []did.DID{currentDIDDocument.ID}

		nextDIDDocument := did.Document{}
		expectedResolverMetadata := &resolver.ResolveMetadata{
			AllowDeactivated: true,
		}
		resolvedMetadata := resolver.DocumentMetadata{}
		test.mockStore.EXPECT().Resolve(*id, expectedResolverMetadata).Return(&currentDIDDocument, &resolvedMetadata, nil)
		err := test.vdr.Update(test.ctx, *id, nextDIDDocument)
		assert.EqualError(t, err, "update DID document: DID Document validation failed: invalid context")
	})

	t.Run("error - can only update did:nuts methods", func(t *testing.T) {
		err := (&Module{}).Update(context.Background(), did.MustParseDID("did:web:example.com"), did.Document{})
		assert.EqualError(t, err, "can't update DID document of type: web")
	})

	t.Run("error - no controller for document", func(t *testing.T) {
		test := newVDRTestCtx(t)
		document := didnuts.CreateDocument()
		document.ID = *id

		expectedResolverMetadata := &resolver.ResolveMetadata{
			AllowDeactivated: true,
		}
		resolvedMetadata := resolver.DocumentMetadata{}
		test.mockStore.EXPECT().Resolve(*id, expectedResolverMetadata).Return(&document, &resolvedMetadata, nil)
		err := test.vdr.Update(test.ctx, *id, document)
		assert.EqualError(t, err, "update DID document: the DID document has been deactivated")
	})
	t.Run("error - could not resolve current document", func(t *testing.T) {
		test := newVDRTestCtx(t)
		nextDIDDocument := did.Document{}
		expectedResolverMetadata := &resolver.ResolveMetadata{
			AllowDeactivated: true,
		}
		test.mockStore.EXPECT().Resolve(*id, expectedResolverMetadata).Return(nil, nil, resolver.ErrNotFound)
		err := test.vdr.Update(test.ctx, *id, nextDIDDocument)
		assert.EqualError(t, err, "update DID document: unable to find the DID document")
	})

	t.Run("error - document not managed by this node", func(t *testing.T) {
		test := newVDRTestCtx(t)
		nextDIDDocument := didnuts.CreateDocument()
		nextDIDDocument.ID = *id
		currentDIDDocument := nextDIDDocument
		currentDIDDocument.AddCapabilityInvocation(&did.VerificationMethod{ID: *keyID})
		test.mockStore.EXPECT().Resolve(*id, gomock.Any()).Times(1).Return(&currentDIDDocument, &resolver.DocumentMetadata{}, nil)
		test.mockKeyStore.EXPECT().Resolve(test.ctx, keyID.String()).Return(nil, crypto.ErrPrivateKeyNotFound)

		err := test.vdr.Update(test.ctx, *id, nextDIDDocument)

		assert.Error(t, err)
		assert.EqualError(t, err, "update DID document: DID document not managed by this node")
		assert.ErrorIs(t, err, resolver.ErrDIDNotManagedByThisNode)
		assert.True(t, errors.Is(err, resolver.ErrDIDNotManagedByThisNode),
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
	DIDDocument := didnuts.CreateDocument()
	DIDDocument.ID = id
	DIDDocument.AddCapabilityInvocation(vm)
	DIDDocument.AddAssertionMethod(vm)
	DIDDocument.AddKeyAgreement(vm)

	t.Run("ok", func(t *testing.T) {
		test := newVDRTestCtx(t)
		expectedPayload, _ := json.Marshal(DIDDocument)

		test.mockKeyStore.EXPECT().New(test.ctx, gomock.Any()).Return(key, nil)
		test.mockNetwork.EXPECT().CreateTransaction(test.ctx, network.TransactionTemplate(expectedPayloadType, expectedPayload, key).WithAttachKey().WithAdditionalPrevs([]hash.SHA256Hash{}))

		didDoc, key, err := test.vdr.Create(test.ctx, didnuts.DefaultCreationOptions())

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
		creationOptions := management.DIDCreationOptions{
			Controllers: []did.DID{controllerID},
			KeyFlags:    management.AssertionMethodUsage | management.CapabilityInvocationUsage | management.KeyAgreementUsage,
			SelfControl: true,
		}
		test.mockKeyStore.EXPECT().New(test.ctx, gomock.Any()).Return(key, nil)
		test.mockStore.EXPECT().Resolve(controllerID, gomock.Any()).Return(&controllerDocument, &resolver.DocumentMetadata{SourceTransactions: refs}, nil)
		test.mockNetwork.EXPECT().CreateTransaction(test.ctx, network.TransactionTemplate(expectedPayloadType, expectedPayload, key).WithAttachKey().WithAdditionalPrevs(refs))

		didDoc, key, err := test.vdr.Create(test.ctx, creationOptions)

		assert.NoError(t, err)
		assert.NotNil(t, didDoc)
		assert.NotNil(t, key)
	})

	t.Run("error - unknown controllers", func(t *testing.T) {
		test := newVDRTestCtx(t)
		creationOptions := management.DIDCreationOptions{
			Controllers: []did.DID{controllerID},
			KeyFlags:    management.AssertionMethodUsage | management.CapabilityInvocationUsage | management.KeyAgreementUsage,
			SelfControl: true,
		}
		test.mockStore.EXPECT().Resolve(controllerID, gomock.Any()).Return(nil, nil, resolver.ErrNotFound)

		_, _, err := test.vdr.Create(test.ctx, creationOptions)

		assert.EqualError(t, err, "could not create DID document: could not resolve a controller: unable to find the DID document")
	})

	t.Run("error - doc creation", func(t *testing.T) {
		test := newVDRTestCtx(t)
		test.mockKeyStore.EXPECT().New(gomock.Any(), gomock.Any()).Return(nil, errors.New("b00m!"))

		_, _, err := test.vdr.Create(test.ctx, didnuts.DefaultCreationOptions())

		assert.EqualError(t, err, "could not create DID document: b00m!")
	})

	t.Run("error - transaction failed", func(t *testing.T) {
		test := newVDRTestCtx(t)
		key := crypto.NewTestKey("did:nuts:123#key-1")
		test.mockKeyStore.EXPECT().New(gomock.Any(), gomock.Any()).Return(key, nil)
		test.mockNetwork.EXPECT().CreateTransaction(gomock.Any(), gomock.Any()).Return(nil, errors.New("b00m!"))

		_, _, err := test.vdr.Create(test.ctx, didnuts.DefaultCreationOptions())

		assert.EqualError(t, err, "could not store DID document in network: b00m!")
	})
}

func TestNewVDR(t *testing.T) {
	vdr := NewVDR(nil, nil, nil, nil)
	assert.IsType(t, &Module{}, vdr)
}

func TestVDR_Start(t *testing.T) {
	t.Run("migration", func(t *testing.T) {
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
	})

}

func TestVDR_ConflictingDocuments(t *testing.T) {
	t.Run("diagnostics", func(t *testing.T) {
		t.Run("ok - no conflicts/no documents", func(t *testing.T) {
			vdr := NewVDR(nil, nil, nil, nil)
			vdr.store = didstore.NewTestStore(t)
			results := vdr.Diagnostics()

			require.Len(t, results, 2)
			assert.Equal(t, "map[owned_count:0 total_count:0]", results[0].String())
			assert.Equal(t, "0", results[1].String())
		})

		t.Run("ok - 1 conflict", func(t *testing.T) {
			vdr := NewVDR(nil, nil, nil, nil)
			vdr.store = didstore.NewTestStore(t)
			didDocument := did.Document{ID: TestDIDA}
			_ = vdr.store.Add(didDocument, didstore.TestTransaction(didDocument))
			_ = vdr.store.Add(didDocument, didstore.TestTransaction(didDocument))
			results := vdr.Diagnostics()

			require.Len(t, results, 2)
			assert.Equal(t, "map[owned_count:0 total_count:1]", results[0].String())
			assert.Equal(t, "1", results[1].String())
		})

		t.Run("ok - 1 owned conflict", func(t *testing.T) {
			client := crypto.NewMemoryCryptoInstance()
			keyID := TestDIDA
			keyID.Fragment = "1"
			_, _ = client.New(audit.TestContext(), crypto.StringNamingFunc(keyID.String()))
			vdr := NewVDR(client, nil, didstore.NewTestStore(t), nil)
			vdr.didResolver.Register(didnuts.MethodName, didnuts.Resolver{Store: vdr.store})
			didDocument := did.Document{ID: TestDIDA}

			didDocument.AddCapabilityInvocation(&did.VerificationMethod{ID: keyID})
			_ = vdr.store.Add(didDocument, didstore.TestTransaction(didDocument))
			_ = vdr.store.Add(didDocument, didstore.TestTransaction(didDocument))
			results := vdr.Diagnostics()

			require.Len(t, results, 2)
			assert.Equal(t, "map[owned_count:1 total_count:1]", results[0].String())
			assert.Equal(t, "1", results[1].String())
		})

		t.Run("ok - 1 owned conflict in controlled document", func(t *testing.T) {
			// vendor
			test := newVDRTestCtx(t)
			keyVendor := crypto.NewTestKey("did:nuts:vendor#keyVendor-1")
			test.mockKeyStore.EXPECT().New(test.ctx, gomock.Any()).Return(keyVendor, nil)
			test.mockNetwork.EXPECT().CreateTransaction(test.ctx, gomock.Any()).AnyTimes()
			didDocVendor, keyVendor, err := test.vdr.Create(test.ctx, didnuts.DefaultCreationOptions())
			require.NoError(t, err)

			// organization
			keyOrg := crypto.NewTestKey("did:nuts:org#keyOrg-1")
			test.mockKeyStore.EXPECT().New(test.ctx, gomock.Any()).Return(keyOrg, nil).Times(2)
			test.mockStore.EXPECT().Resolve(didDocVendor.ID, nil).Return(didDocVendor, &resolver.DocumentMetadata{}, nil)
			didDocOrg, keyOrg, err := test.vdr.Create(test.ctx, management.DIDCreationOptions{
				Controllers: []did.DID{didDocVendor.ID},
				KeyFlags:    management.AssertionMethodUsage | management.KeyAgreementUsage,
				SelfControl: false,
			})
			require.NoError(t, err)

			client := crypto.NewMemoryCryptoInstance()
			_, _ = client.New(audit.TestContext(), crypto.StringNamingFunc(keyVendor.KID()))
			_, _ = client.New(audit.TestContext(), crypto.StringNamingFunc(keyOrg.KID()))
			vdr := NewVDR(client, nil, didstore.NewTestStore(t), nil)
			vdr.didResolver.Register(didnuts.MethodName, didnuts.Resolver{Store: vdr.store})

			_ = vdr.store.Add(*didDocVendor, didstore.TestTransaction(*didDocVendor))
			_ = vdr.store.Add(*didDocOrg, didstore.TestTransaction(*didDocOrg))
			_ = vdr.store.Add(*didDocOrg, didstore.TestTransaction(*didDocOrg))
			results := vdr.Diagnostics()

			require.Len(t, results, 2)
			assert.Equal(t, "map[owned_count:1 total_count:1]", results[0].String())
			assert.Equal(t, "2", results[1].String())
		})
	})
	t.Run("list", func(t *testing.T) {
		t.Run("ok - no conflicts", func(t *testing.T) {
			vdr := NewVDR(nil, nil, nil, nil)
			vdr.store = didstore.NewTestStore(t)
			docs, meta, err := vdr.ConflictedDocuments()

			require.NoError(t, err)
			assert.Len(t, docs, 0)
			assert.Len(t, meta, 0)
		})

		t.Run("ok - 1 conflict", func(t *testing.T) {
			vdr := NewVDR(nil, nil, nil, nil)
			vdr.store = didstore.NewTestStore(t)
			didDocument := did.Document{ID: TestDIDA}
			_ = vdr.store.Add(didDocument, didstore.TestTransaction(didDocument))
			_ = vdr.store.Add(didDocument, didstore.TestTransaction(didDocument))
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

		assert.Equal(t, resolver.ErrDIDNotManagedByThisNode, err)
	})
}

func TestWithJSONLDContext(t *testing.T) {
	id, _ := did.ParseDID("did:nuts:123")
	expected := did.Document{ID: *id, Context: []ssi.URI{didnuts.NutsDIDContextV1URI()}}

	t.Run("added if not present", func(t *testing.T) {
		document := did.Document{ID: *id}

		patched := withJSONLDContext(document, didnuts.NutsDIDContextV1URI())

		assert.EqualValues(t, expected.Context, patched.Context)
	})

	t.Run("no changes if existing", func(t *testing.T) {
		patched := withJSONLDContext(expected, didnuts.NutsDIDContextV1URI())

		assert.EqualValues(t, expected.Context, patched.Context)
	})
}

func TestVDR_IsOwner(t *testing.T) {
	id := did.MustParseDID("did:nuts:123")
	t.Run("delegates the call to the underlying DocumentOwner", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		owner := management.NewMockDocumentOwner(ctrl)
		owner.EXPECT().IsOwner(gomock.Any(), id).Return(true, nil)

		result, err := (&Module{documentOwner: owner}).IsOwner(context.Background(), id)

		assert.NoError(t, err)
		assert.True(t, result)
	})
}

func TestVDR_Configure(t *testing.T) {
	t.Run("it can resolve using did:web", func(t *testing.T) {
		http.DefaultTransport = roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				Header:     map[string][]string{"Content-Type": {"application/json"}},
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"id": "did:web:example.com"}`)),
			}, nil
		})

		instance := NewVDR(nil, nil, nil, nil)
		err := instance.Configure(core.ServerConfig{})
		require.NoError(t, err)

		doc, md, err := instance.Resolver().Resolve(did.MustParseDID("did:web:example.com"), nil)

		assert.NoError(t, err)
		assert.NotNil(t, doc)
		assert.NotNil(t, md)
	})
	t.Run("it can resolve using did:jwk", func(t *testing.T) {
		privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		expectedJWK, err := jwk.New(privateKey.Public())
		require.NoError(t, err)

		jwkBytes, _ := json.Marshal(expectedJWK)
		inputDIDString := "did:jwk:" + base64.URLEncoding.EncodeToString(jwkBytes)
		inputDID, err := did.ParseDID(inputDIDString)
		require.NoError(t, err)

		instance := NewVDR(nil, nil, nil, nil)
		err = instance.Configure(core.ServerConfig{})
		require.NoError(t, err)

		doc, md, err := instance.Resolver().Resolve(*inputDID, nil)

		assert.NoError(t, err)
		assert.NotNil(t, doc)
		assert.NotNil(t, md)
		// Basic assertion on the actual key
		require.Len(t, doc.VerificationMethod, 1)
		assert.Equal(t, "P-256", doc.VerificationMethod[0].PublicKeyJwk["crv"])
	})
	t.Run("it can resolve using did:key", func(t *testing.T) {
		instance := NewVDR(nil, nil, nil, nil)
		err := instance.Configure(core.ServerConfig{})
		require.NoError(t, err)

		doc, md, err := instance.Resolver().Resolve(did.MustParseDID("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"), nil)

		assert.NoError(t, err)
		assert.NotNil(t, doc)
		assert.NotNil(t, md)
	})
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (fn roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return fn(r)
}

func TestVDR_DeriveWebDIDDocument(t *testing.T) {
	nutsDID := did.MustParseDID("did:nuts:123")
	webDID := did.MustParseDID("did:web:example.com:iam:123")
	baseURL, _ := url.Parse("https://example.com/iam")
	nutsDIDDoc := did.Document{
		ID:         nutsDID,
		Controller: []did.DID{nutsDID},
		Service: []did.Service{
			{
				ID:              ssi.MustParseURI(nutsDID.String() + "#service1"),
				Type:            "eOverdracht-sender",
				ServiceEndpoint: ssi.MustParseURI(nutsDID.String() + "#service2"),
			},
		},
		VerificationMethod: []*did.VerificationMethod{
			{
				ID:         did.MustParseDIDURL(nutsDID.String() + "#key1"),
				Controller: nutsDID,
			},
		},
		CapabilityInvocation: []did.VerificationRelationship{
			{
				VerificationMethod: &did.VerificationMethod{
					ID:         did.MustParseDIDURL(nutsDID.String() + "#key1"),
					Controller: nutsDID,
				},
			},
		},
	}
	expectedWebDIDDoc := did.Document{
		ID: webDID,
		AlsoKnownAs: []ssi.URI{
			nutsDID.URI(),
		},
		VerificationMethod: []*did.VerificationMethod{
			{
				ID:         did.MustParseDIDURL(webDID.String() + "#key1"),
				Controller: webDID,
			},
		},
		CapabilityInvocation: []did.VerificationRelationship{
			{
				VerificationMethod: &did.VerificationMethod{
					ID:         did.MustParseDIDURL(webDID.String() + "#key1"),
					Controller: webDID,
				},
			},
		},
	}
	// remarshal expectedWebDIDDoc to make sure in-memory format is the same as the one returned by the API
	data, _ := expectedWebDIDDoc.MarshalJSON()
	_ = expectedWebDIDDoc.UnmarshalJSON(data)

	t.Run("ok", func(t *testing.T) {
		ctx := newVDRTestCtx(t)

		ctx.mockStore.EXPECT().Resolve(nutsDID, nil).Return(&nutsDIDDoc, nil, nil)
		ctx.mockOwner.EXPECT().IsOwner(gomock.Any(), nutsDID).Return(true, nil)

		actual, err := ctx.vdr.DeriveWebDIDDocument(nil, *baseURL, nutsDID)

		require.NoError(t, err)
		assert.Equal(t, expectedWebDIDDoc, *actual)
	})
	t.Run("not owned by the node", func(t *testing.T) {
		ctx := newVDRTestCtx(t)

		ctx.mockStore.EXPECT().Resolve(nutsDID, nil).Return(&nutsDIDDoc, nil, nil)
		ctx.mockOwner.EXPECT().IsOwner(gomock.Any(), nutsDID).Return(false, nil)

		actual, err := ctx.vdr.DeriveWebDIDDocument(nil, *baseURL, nutsDID)

		assert.ErrorIs(t, err, resolver.ErrNotFound)
		assert.Nil(t, actual)
	})
	t.Run("resolver error", func(t *testing.T) {
		ctx := newVDRTestCtx(t)

		ctx.mockStore.EXPECT().Resolve(nutsDID, nil).Return(nil, nil, resolver.ErrNotFound)

		actual, err := ctx.vdr.DeriveWebDIDDocument(nil, *baseURL, nutsDID)

		assert.ErrorIs(t, err, resolver.ErrNotFound)
		assert.Nil(t, actual)
	})
	t.Run("ownership check error", func(t *testing.T) {
		ctx := newVDRTestCtx(t)

		ctx.mockStore.EXPECT().Resolve(nutsDID, nil).Return(&nutsDIDDoc, nil, nil)
		ctx.mockOwner.EXPECT().IsOwner(gomock.Any(), nutsDID).Return(false, errors.New("failed"))

		actual, err := ctx.vdr.DeriveWebDIDDocument(nil, *baseURL, nutsDID)

		assert.EqualError(t, err, "failed")
		assert.Nil(t, actual)
	})
}
