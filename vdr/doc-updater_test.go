package vdr

import (
	"encoding/json"
	"errors"
	"testing"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vdr/doc"
	"github.com/stretchr/testify/assert"

	"github.com/golang/mock/gomock"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

// testCtx contains the controller and mocks needed fot testing the DocUpdater
type testCtx struct {
	ctrl            *gomock.Controller
	mockVDR         *types.MockVDR
	mockDocResolver *types.MockDocResolver
	mockKeyStore    *crypto.MockKeyStore
	updater         *DocUpdater
}

func newTestCtx(t *testing.T) testCtx {
	t.Helper()
	ctrl := gomock.NewController(t)
	vdrMock := types.NewMockVDR(ctrl)
	docResolver := types.NewMockDocResolver(ctrl)
	mockKeyStore := crypto.NewMockKeyStore(ctrl)
	t.Cleanup(func() {
		ctrl.Finish()
	})
	kc := &mockKeyCreator{kid: "did:nuts:123"}
	return testCtx{
		ctrl:            ctrl,
		mockVDR:         vdrMock,
		mockDocResolver: docResolver,
		mockKeyStore:    mockKeyStore,
		updater:         &DocUpdater{VDR: vdrMock, KeyCreator: kc, Resolver: docResolver},
	}
}

func Test_newNamingFnForExistingDID(t *testing.T) {
	existingDID, _ := did.ParseDID("did:nuts:123")
	fn := newNamingFnForExistingDID(*existingDID)
	if !assert.NotNil(t, fn) {
		return
	}

	t.Run("it creates a new did", func(t *testing.T) {
		key := crypto.NewTestKey("kid")
		keyID, err := fn(key.Public())
		if !assert.NoError(t, err) {
			return
		}
		assert.NotEmpty(t, keyID)
		newDID, err := did.ParseDID(keyID)
		if !assert.NoError(t, err) {
			return
		}

		assert.Equal(t, newDID.ID, existingDID.ID,
			"expected the base to be the same as the existing DID")
	})
	t.Run("error on empty key", func(t *testing.T) {
		keyID, err := fn(nil)
		assert.EqualError(t, err, "jwk.New requires a non-nil key")
		assert.Empty(t, keyID)
	})
}

func TestNutsDocUpdater_RemoveVerificationMethod(t *testing.T) {
	id123, _ := did.ParseDID("did:nuts:123")
	id123Method, _ := did.ParseDID("did:nuts:123#method-1")
	doc := &did.Document{ID: *id123}
	publicKey := crypto.NewTestKey("did:nuts:123").Public()
	vm, _ := did.NewVerificationMethod(*id123Method, ssi.JsonWebKey2020, did.DID{}, publicKey)
	doc.AddCapabilityInvocation(vm)
	assert.Equal(t, vm, doc.CapabilityInvocation[0].VerificationMethod)
	assert.Equal(t, vm, doc.VerificationMethod[0])

	t.Run("ok", func(t *testing.T) {
		ctx := newTestCtx(t)
		ctx.mockDocResolver.EXPECT().Resolve(*id123, &types.ResolveMetadata{AllowDeactivated: true}).Return(doc, &types.DocumentMetadata{}, nil)
		ctx.mockVDR.EXPECT().Update(*id123, hash.SHA256Hash{}, did.Document{ID: *id123}, nil)

		err := ctx.updater.RemoveVerificationMethod(*id123, *id123Method)
		if !assert.NoError(t, err) {
			return
		}
		assert.Empty(t, doc.CapabilityInvocation)
		assert.Empty(t, doc.VerificationMethod)
	})

	t.Run("error - verificationMethod is not part of the document", func(t *testing.T) {
		ctx := newTestCtx(t)
		ctx.mockDocResolver.EXPECT().Resolve(*id123, &types.ResolveMetadata{AllowDeactivated: true}).Return(&did.Document{ID: *id123}, &types.DocumentMetadata{}, nil)

		err := ctx.updater.RemoveVerificationMethod(*id123, *id123Method)
		assert.EqualError(t, err, "verificationMethod not found in document")
	})

	t.Run("error - document is deactivated", func(t *testing.T) {
		ctx := newTestCtx(t)
		ctx.mockDocResolver.EXPECT().Resolve(*id123, &types.ResolveMetadata{AllowDeactivated: true}).Return(&did.Document{ID: *id123}, &types.DocumentMetadata{Deactivated: true}, nil)

		err := ctx.updater.RemoveVerificationMethod(*id123, *id123Method)
		assert.EqualError(t, err, "the DID document has been deactivated")
		assert.True(t, errors.Is(err, types.ErrDeactivated))
	})
}

func TestNutsDocUpdater_CreateNewAuthenticationMethodForDID(t *testing.T) {
	id123, _ := did.ParseDID("did:nuts:123")

	kc := &mockKeyCreator{kid: "did:nuts:123#J9O6wvqtYOVwjc8JtZ4aodRdbPv_IKAjLkEq9uHlDdE"}
	updater := DocUpdater{KeyCreator: kc}

	t.Run("ok", func(t *testing.T) {
		// Prepare a document with an authenticationMethod:
		document := &did.Document{ID: *id123}
		method, err := updater.createNewVerificationMethodForDID(document.ID)
		if !assert.NoError(t, err) {
			return
		}
		document.AddCapabilityInvocation(method)

		assert.NotNil(t, method)
		assert.Len(t, document.CapabilityInvocation, 1)
		assert.Equal(t, method.ID.String(), document.CapabilityInvocation[0].ID.String())
		assert.Equal(t, "did:nuts:123#J9O6wvqtYOVwjc8JtZ4aodRdbPv_IKAjLkEq9uHlDdE", document.CapabilityInvocation[0].ID.String())
	})

}

func TestNutsDocUpdater_AddKey(t *testing.T) {
	id, _ := did.ParseDID("did:nuts:123")
	keyID, _ := did.ParseDID("did:nuts:123#key-1")
	currentHash := hash.SHA256Sum([]byte("currentHash"))

	t.Run("ok - add a new key", func(t *testing.T) {
		ctx := newTestCtx(t)

		currentDIDDocument := did.Document{ID: *id, Controller: []did.DID{*id}}
		currentDIDDocument.AddCapabilityInvocation(&did.VerificationMethod{ID: *keyID})
		ctx.mockDocResolver.EXPECT().Resolve(*id, &types.ResolveMetadata{AllowDeactivated: true}).Return(&currentDIDDocument, &types.DocumentMetadata{Hash: currentHash}, nil)
		var updatedDocument did.Document
		ctx.mockVDR.EXPECT().Update(*id, currentHash, gomock.Any(), nil).Do(func(_ did.DID, _ interface{}, doc did.Document, _ interface{}) {
			updatedDocument = doc
		})

		key, err := ctx.updater.AddVerificationMethod(*id)
		if !assert.NoError(t, err) {
			return
		}
		assert.NotNil(t, key)
		assert.Equal(t, key.Controller, *id,
			"expected method to have DID as controller")
		assert.Len(t, updatedDocument.VerificationMethod, 2)
		assert.Contains(t, updatedDocument.VerificationMethod, key)
	})

	t.Run("error - vdr.update throws an error", func(t *testing.T) {
		ctx := newTestCtx(t)

		currentDIDDocument := did.Document{ID: *id, Controller: []did.DID{*id}}
		currentDIDDocument.AddCapabilityInvocation(&did.VerificationMethod{ID: *keyID})
		ctx.mockDocResolver.EXPECT().Resolve(*id, &types.ResolveMetadata{AllowDeactivated: true}).Return(&currentDIDDocument, &types.DocumentMetadata{Hash: currentHash}, nil)
		ctx.mockVDR.EXPECT().Update(*id, currentHash, gomock.Any(), nil).Return(types.ErrNotFound)

		key, err := ctx.updater.AddVerificationMethod(*id)
		if !assert.Error(t, err) {
			return
		}
		assert.True(t, errors.Is(err, types.ErrNotFound))
		assert.Nil(t, key)
	})

	t.Run("error - did is deactivated", func(t *testing.T) {
		ctx := newTestCtx(t)

		currentDIDDocument := did.Document{ID: *id, Controller: []did.DID{*id}}
		ctx.mockDocResolver.EXPECT().Resolve(*id, &types.ResolveMetadata{AllowDeactivated: true}).Return(&currentDIDDocument, &types.DocumentMetadata{Hash: currentHash, Deactivated: true}, nil)

		key, err := ctx.updater.AddVerificationMethod(*id)
		if !assert.Error(t, err) {
			return
		}
		assert.True(t, errors.Is(err, types.ErrDeactivated))
		assert.Nil(t, key)
	})
}

func TestNutsDocUpdater_Deactivate(t *testing.T) {
	id, _ := did.ParseDID("did:nuts:123")
	keyID, _ := did.ParseDID("did:nuts:123#key-1")
	currentHash := hash.SHA256Sum([]byte("currentHash"))

	ctx := newVDRTestCtx(t)
	updater := DocUpdater{VDR: ctx.vdr, Resolver: doc.Resolver{Store: ctx.mockStore}, KeyCreator: ctx.mockKeyStore}

	expectedDocument := did.Document{ID: *id, Context: []ssi.URI{did.DIDContextV1URI()}}
	expectedPayload, _ := json.Marshal(expectedDocument)

	currentDIDDocument := did.Document{ID: *id, Controller: []did.DID{*id}}
	currentDIDDocument.AddCapabilityInvocation(&did.VerificationMethod{ID: *keyID})

	key := crypto.NewTestKey(keyID.String())
	ctx.mockKeyStore.EXPECT().Signer(keyID.String()).Return(key, nil)
	ctx.mockNetwork.EXPECT().CreateTransaction(expectedPayloadType, expectedPayload, key, false, gomock.Any(), gomock.Any())
	gomock.InOrder(
		ctx.mockStore.EXPECT().Resolve(*id, &types.ResolveMetadata{AllowDeactivated: true}).Return(&currentDIDDocument, &types.DocumentMetadata{Hash: currentHash}, nil),
		ctx.mockStore.EXPECT().Resolve(*id, &types.ResolveMetadata{Hash: &currentHash, AllowDeactivated: true}).Return(&currentDIDDocument, &types.DocumentMetadata{}, nil),
	)

	err := updater.Deactivate(*id)
	if !assert.NoError(t, err) {
		return
	}
}

func Test_getVerificationMethodDiff(t *testing.T) {
	idMethod1, _ := did.ParseDID("did:nuts:123#method1")
	idMethod2, _ := did.ParseDID("did:nuts:123#method2")
	t.Run("empty documents", func(t *testing.T) {
		docA := did.Document{}
		docB := did.Document{}
		newMethods, removed := getVerificationMethodDiff(docA, docB)

		assert.Len(t, removed, 0)
		assert.Len(t, newMethods, 0)
	})

	t.Run("a new verificationMethod", func(t *testing.T) {
		docA := did.Document{}
		docB := did.Document{}
		newMethod := &did.VerificationMethod{ID: *idMethod1}
		docB.VerificationMethod.Add(newMethod)

		newMethods, removed := getVerificationMethodDiff(docA, docB)

		assert.Len(t, removed, 0)
		assert.Len(t, newMethods, 1)
		assert.Equal(t, newMethod, newMethods[0])
	})

	t.Run("a new and an old verificationMethod", func(t *testing.T) {
		docA := did.Document{}
		oldMethod := &did.VerificationMethod{ID: *idMethod1}
		docA.VerificationMethod.Add(oldMethod)

		docB := did.Document{}
		newMethod := &did.VerificationMethod{ID: *idMethod2}
		docB.VerificationMethod.Add(newMethod)

		newMethods, oldMethods := getVerificationMethodDiff(docA, docB)

		assert.Len(t, oldMethods, 1)
		assert.Len(t, newMethods, 1)
		assert.Equal(t, newMethod, newMethods[0])
		assert.Equal(t, oldMethod, oldMethods[0])
	})

	t.Run("no changes to the methods", func(t *testing.T) {
		method := &did.VerificationMethod{ID: *idMethod1}
		docA := did.Document{}
		docA.VerificationMethod.Add(method)

		docB := did.Document{}
		docB.VerificationMethod.Add(method)

		newMethods, oldMethods := getVerificationMethodDiff(docA, docB)

		assert.Len(t, oldMethods, 0)
		assert.Len(t, newMethods, 0)
	})

}
