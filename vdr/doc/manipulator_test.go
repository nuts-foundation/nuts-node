package doc

import (
	"errors"
	"testing"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/stretchr/testify/assert"

	"github.com/golang/mock/gomock"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

// manipulatorTestContext contains the controller and mocks needed for testing the Manipulator
type manipulatorTestContext struct {
	ctrl           *gomock.Controller
	mockUpdater    *types.MockDocUpdater
	mockResolver   *types.MockDocResolver
	mockKeyCreator *mockKeyCreator
	manipulator    *Manipulator
}

func newManipulatorTestContext(t *testing.T) manipulatorTestContext {
	t.Helper()
	ctrl := gomock.NewController(t)
	updater := types.NewMockDocUpdater(ctrl)
	resolver := types.NewMockDocResolver(ctrl)
	t.Cleanup(func() {
		ctrl.Finish()
	})
	keyCreator := newMockKeyCreator()
	return manipulatorTestContext{
		ctrl:           ctrl,
		mockUpdater:    updater,
		mockResolver:   resolver,
		mockKeyCreator: keyCreator,
		manipulator:    &Manipulator{Updater: updater, KeyCreator: keyCreator, Resolver: resolver},
	}
}

func TestManipulator_RemoveVerificationMethod(t *testing.T) {
	id123, _ := did.ParseDID("did:nuts:123")
	id123Method, _ := did.ParseDID("did:nuts:123#method-1")
	doc := &did.Document{ID: *id123}
	publicKey := crypto.NewTestKey("did:nuts:123").Public()
	vm, _ := did.NewVerificationMethod(*id123Method, ssi.JsonWebKey2020, did.DID{}, publicKey)
	doc.AddCapabilityInvocation(vm)
	assert.Equal(t, vm, doc.CapabilityInvocation[0].VerificationMethod)
	assert.Equal(t, vm, doc.VerificationMethod[0])

	t.Run("ok", func(t *testing.T) {
		ctx := newManipulatorTestContext(t)
		ctx.mockResolver.EXPECT().Resolve(*id123, &types.ResolveMetadata{AllowDeactivated: true}).Return(doc, &types.DocumentMetadata{}, nil)
		ctx.mockUpdater.EXPECT().Update(*id123, hash.SHA256Hash{}, did.Document{ID: *id123}, nil)

		err := ctx.manipulator.RemoveVerificationMethod(*id123, *id123Method)
		if !assert.NoError(t, err) {
			return
		}
		assert.Empty(t, doc.CapabilityInvocation)
		assert.Empty(t, doc.VerificationMethod)
	})

	t.Run("error - verificationMethod is not part of the document", func(t *testing.T) {
		ctx := newManipulatorTestContext(t)
		ctx.mockResolver.EXPECT().Resolve(*id123, &types.ResolveMetadata{AllowDeactivated: true}).Return(&did.Document{ID: *id123}, &types.DocumentMetadata{}, nil)

		err := ctx.manipulator.RemoveVerificationMethod(*id123, *id123Method)
		assert.EqualError(t, err, "verificationMethod not found in document")
	})

	t.Run("error - document is deactivated", func(t *testing.T) {
		ctx := newManipulatorTestContext(t)
		ctx.mockResolver.EXPECT().Resolve(*id123, &types.ResolveMetadata{AllowDeactivated: true}).Return(&did.Document{ID: *id123}, &types.DocumentMetadata{Deactivated: true}, nil)

		err := ctx.manipulator.RemoveVerificationMethod(*id123, *id123Method)
		assert.EqualError(t, err, "the DID document has been deactivated")
		assert.True(t, errors.Is(err, types.ErrDeactivated))
	})
}

func TestManipulator_CreateNewAuthenticationMethodForDID(t *testing.T) {
	id123, _ := did.ParseDID("did:nuts:123")

	kc := newMockKeyCreator()

	t.Run("ok", func(t *testing.T) {
		// Prepare a document with an authenticationMethod:
		document := &did.Document{ID: *id123}
		method, err := CreateNewVerificationMethodForDID(document.ID, kc)
		if !assert.NoError(t, err) {
			return
		}
		document.AddCapabilityInvocation(method)

		assert.NotNil(t, method)
		assert.Len(t, document.CapabilityInvocation, 1)
		assert.Equal(t, method.ID.String(), document.CapabilityInvocation[0].ID.String())
		assert.Equal(t, kc.kid, document.CapabilityInvocation[0].ID.String())
	})
}

func TestManipulator_AddKey(t *testing.T) {
	id, _ := did.ParseDID("did:nuts:123")
	keyID, _ := did.ParseDID("did:nuts:123#key-1")
	currentHash := hash.SHA256Sum([]byte("currentHash"))

	t.Run("ok - add a new key", func(t *testing.T) {
		ctx := newManipulatorTestContext(t)

		currentDIDDocument := did.Document{ID: *id, Controller: []did.DID{*id}}
		currentDIDDocument.AddCapabilityInvocation(&did.VerificationMethod{ID: *keyID})
		ctx.mockResolver.EXPECT().Resolve(*id, &types.ResolveMetadata{AllowDeactivated: true}).Return(&currentDIDDocument, &types.DocumentMetadata{Hash: currentHash}, nil)
		var updatedDocument did.Document
		ctx.mockUpdater.EXPECT().Update(*id, currentHash, gomock.Any(), nil).Do(func(_ did.DID, _ interface{}, doc did.Document, _ interface{}) {
			updatedDocument = doc
		})

		key, err := ctx.manipulator.AddVerificationMethod(*id)
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
		ctx := newManipulatorTestContext(t)

		currentDIDDocument := did.Document{ID: *id, Controller: []did.DID{*id}}
		currentDIDDocument.AddCapabilityInvocation(&did.VerificationMethod{ID: *keyID})
		ctx.mockResolver.EXPECT().Resolve(*id, &types.ResolveMetadata{AllowDeactivated: true}).Return(&currentDIDDocument, &types.DocumentMetadata{Hash: currentHash}, nil)
		ctx.mockUpdater.EXPECT().Update(*id, currentHash, gomock.Any(), nil).Return(types.ErrNotFound)

		key, err := ctx.manipulator.AddVerificationMethod(*id)
		if !assert.Error(t, err) {
			return
		}
		assert.True(t, errors.Is(err, types.ErrNotFound))
		assert.Nil(t, key)
	})

	t.Run("error - did is deactivated", func(t *testing.T) {
		ctx := newManipulatorTestContext(t)

		currentDIDDocument := did.Document{ID: *id, Controller: []did.DID{*id}}
		ctx.mockResolver.EXPECT().Resolve(*id, &types.ResolveMetadata{AllowDeactivated: true}).Return(&currentDIDDocument, &types.DocumentMetadata{Hash: currentHash, Deactivated: true}, nil)

		key, err := ctx.manipulator.AddVerificationMethod(*id)
		if !assert.Error(t, err) {
			return
		}
		assert.True(t, errors.Is(err, types.ErrDeactivated))
		assert.Nil(t, key)
	})
}

func TestManipulator_Deactivate(t *testing.T) {
	id, _ := did.ParseDID("did:nuts:123")
	keyID, _ := did.ParseDID("did:nuts:123#key-1")
	currentHash := hash.SHA256Sum([]byte("currentHash"))

	ctx := newManipulatorTestContext(t)

	currentDIDDocument := did.Document{ID: *id, Controller: []did.DID{*id}}
	currentDIDDocument.AddCapabilityInvocation(&did.VerificationMethod{ID: *keyID})

	ctx.mockResolver.EXPECT().Resolve(*id, &types.ResolveMetadata{AllowDeactivated: true}).Return(&currentDIDDocument, &types.DocumentMetadata{Hash: currentHash}, nil)
	ctx.mockUpdater.EXPECT().Update(*id, currentHash, did.Document{Context: []ssi.URI{did.DIDContextV1URI()}, ID: *id}, nil)

	err := ctx.manipulator.Deactivate(*id)
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
