package vdr

import (
	"encoding/json"
	"errors"
	"testing"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/stretchr/testify/assert"

	"github.com/golang/mock/gomock"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

// testCtx contains the controller and mocks needed fot testing the NutsDocUpdater
type testCtx struct {
	ctrl    *gomock.Controller
	vdrMock *types.MockVDR
	updater *NutsDocUpdater
}

func newTestCtx(t *testing.T) testCtx {
	t.Helper()
	ctrl := gomock.NewController(t)
	vdrMock := types.NewMockVDR(ctrl)
	t.Cleanup(func() {
		ctrl.Finish()
	})
	return testCtx{
		ctrl:    ctrl,
		vdrMock: vdrMock,
		updater: &NutsDocUpdater{VDR: vdrMock},
	}
}

func Test_newNamingFnForExistingDID(t *testing.T) {
	existingDID, _ := did.ParseDID("did:nuts:123")
	fn := newNamingFnForExistingDID(*existingDID)
	if !assert.NotNil(t, fn) {
		return
	}

	t.Run("it creates a new did", func(t *testing.T) {
		rawKey, err := jwkToPublicKey(t, jwkString)
		keyID, err := fn(rawKey)
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
		assert.Equal(t, newDID.Fragment, "J9O6wvqtYOVwjc8JtZ4aodRdbPv_IKAjLkEq9uHlDdE",
			"expected the fragment to be derived from the public key")
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
	publicKey, _ := jwkToPublicKey(t, jwkString)
	vm, _ := did.NewVerificationMethod(*id123Method, ssi.JsonWebKey2020, did.DID{}, publicKey)
	doc.AddAuthenticationMethod(vm)
	assert.Equal(t, vm, doc.Authentication[0].VerificationMethod)
	assert.Equal(t, vm, doc.VerificationMethod[0])

	t.Run("ok", func(t *testing.T) {
		ctx := newTestCtx(t)
		ctx.vdrMock.EXPECT().Resolve(*id123, &types.ResolveMetadata{AllowDeactivated: true}).Return(doc, &types.DocumentMetadata{}, nil)
		ctx.vdrMock.EXPECT().Update(*id123, hash.SHA256Hash{}, did.Document{ID: *id123}, nil)

		err := ctx.updater.RemoveVerificationMethod(*id123, *id123Method)
		if !assert.NoError(t, err) {
			return
		}
		assert.Empty(t, doc.Authentication)
		assert.Empty(t, doc.VerificationMethod)
	})

	t.Run("error - verificationMethod is not part of the document", func(t *testing.T) {
		ctx := newTestCtx(t)
		ctx.vdrMock.EXPECT().Resolve(*id123, &types.ResolveMetadata{AllowDeactivated: true}).Return(&did.Document{ID: *id123}, &types.DocumentMetadata{}, nil)

		err := ctx.updater.RemoveVerificationMethod(*id123, *id123Method)
		assert.EqualError(t, err, "verificationMethod not found in document")
	})

	t.Run("error - document is deactivated", func(t *testing.T) {
		ctx := newTestCtx(t)
		ctx.vdrMock.EXPECT().Resolve(*id123, &types.ResolveMetadata{AllowDeactivated: true}).Return(&did.Document{ID: *id123}, &types.DocumentMetadata{Deactivated: true}, nil)

		err := ctx.updater.RemoveVerificationMethod(*id123, *id123Method)
		assert.EqualError(t, err, "the document has been deactivated")
		assert.True(t, errors.Is(err, types.ErrDeactivated))
	})
}

func TestNutsDocUpdater_CreateNewAuthenticationMethodForDID(t *testing.T) {
	id123, _ := did.ParseDID("did:nuts:123")

	keyCreator := &mockKeyCreator{
		t:      t,
		jwkStr: jwkString,
	}

	updater := NutsDocUpdater{KeyCreator: keyCreator}

	t.Run("ok", func(t *testing.T) {
		// Prepare a document with an authenticationMethod:
		document := &did.Document{ID: *id123}
		method, err := updater.createNewVerificationMethodForDID(document.ID)
		if !assert.NoError(t, err) {
			return
		}
		document.AddAuthenticationMethod(method)

		assert.NotNil(t, method)
		assert.Len(t, document.Authentication, 1)
		assert.Equal(t, method.ID.String(), document.Authentication[0].ID.String())
		assert.Equal(t, "did:nuts:123#J9O6wvqtYOVwjc8JtZ4aodRdbPv_IKAjLkEq9uHlDdE", document.Authentication[0].ID.String())
	})

}

func TestNutsDocUpdater_AddKey(t *testing.T) {
	id, _ := did.ParseDID("did:nuts:123")
	keyID, _ := did.ParseDID("did:nuts:123#key-1")
	currentHash := hash.SHA256Sum([]byte("currentHash"))

	t.Run("ok - add a new key", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		keyCreator := &mockKeyCreator{
			t:      t,
			jwkStr: jwkString,
		}
		vdrMock := types.NewMockVDR(ctrl)
		currentDIDDocument := did.Document{ID: *id, Controller: []did.DID{*id}}
		currentDIDDocument.AddAuthenticationMethod(&did.VerificationMethod{ID: *keyID})
		vdrMock.EXPECT().Resolve(*id, &types.ResolveMetadata{AllowDeactivated: true}).Return(&currentDIDDocument, &types.DocumentMetadata{Hash: currentHash}, nil)
		var updatedDocument did.Document
		vdrMock.EXPECT().Update(*id, currentHash, gomock.Any(), nil).Do(func(_ did.DID, _ interface{}, doc did.Document, _ interface{}) {
			updatedDocument = doc
		})

		var keyAdder types.DocKeyAdder = NutsDocUpdater{VDR: vdrMock, KeyCreator: keyCreator}

		key, err := keyAdder.AddVerificationMethod(*id)
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
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		keyCreator := &mockKeyCreator{
			t:      t,
			jwkStr: jwkString,
		}
		vdrMock := types.NewMockVDR(ctrl)
		currentDIDDocument := did.Document{ID: *id, Controller: []did.DID{*id}}
		currentDIDDocument.AddAuthenticationMethod(&did.VerificationMethod{ID: *keyID})
		vdrMock.EXPECT().Resolve(*id, &types.ResolveMetadata{AllowDeactivated: true}).Return(&currentDIDDocument, &types.DocumentMetadata{Hash: currentHash}, nil)
		vdrMock.EXPECT().Update(*id, currentHash, gomock.Any(), nil).Return(types.ErrNotFound)

		var keyAdder types.DocKeyAdder = NutsDocUpdater{VDR: vdrMock, KeyCreator: keyCreator}

		key, err := keyAdder.AddVerificationMethod(*id)
		if !assert.Error(t, err) {
			return
		}
		assert.True(t, errors.Is(err, types.ErrNotFound))
		assert.Nil(t, key)
	})

	t.Run("error - did is deactivated", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		vdrMock := types.NewMockVDR(ctrl)
		currentDIDDocument := did.Document{ID: *id, Controller: []did.DID{*id}}
		vdrMock.EXPECT().Resolve(*id, &types.ResolveMetadata{AllowDeactivated: true}).Return(&currentDIDDocument, &types.DocumentMetadata{Hash: currentHash, Deactivated: true}, nil)

		var keyAdder types.DocKeyAdder = NutsDocUpdater{VDR: vdrMock}

		key, err := keyAdder.AddVerificationMethod(*id)
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

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	didStoreMock := types.NewMockStore(ctrl)
	networkMock := network.NewMockTransactions(ctrl)
	vdr := VDR{
		store:   didStoreMock,
		network: networkMock,
	}
	updater := NutsDocUpdater{VDR: &vdr}

	expectedDocument := did.Document{ID: *id, Context: []ssi.URI{did.DIDContextV1URI()}}
	expectedPayload, _ := json.Marshal(expectedDocument)

	currentDIDDocument := did.Document{ID: *id, Controller: []did.DID{*id}}
	currentDIDDocument.AddAuthenticationMethod(&did.VerificationMethod{ID: *keyID})

	networkMock.EXPECT().CreateTransaction(expectedPayloadType, expectedPayload, keyID.String(), nil, gomock.Any(), gomock.Any(), gomock.Any())
	gomock.InOrder(
		didStoreMock.EXPECT().Resolve(*id, &types.ResolveMetadata{AllowDeactivated: true}).Return(&currentDIDDocument, &types.DocumentMetadata{Hash: currentHash}, nil),
		didStoreMock.EXPECT().Resolve(*id, &types.ResolveMetadata{Hash: &currentHash, AllowDeactivated: true}).Return(&currentDIDDocument, &types.DocumentMetadata{}, nil),
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
