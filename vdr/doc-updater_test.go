package vdr

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/stretchr/testify/assert"
	"testing"
)

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
	updater := NutsDocUpdater{}

	t.Run("ok", func(t *testing.T) {
		doc := &did.Document{ID: *id123}
		publicKey, _ := jwkToPublicKey(t, jwkString)
		vm, _ := did.NewVerificationMethod(*id123Method, ssi.JsonWebKey2020, did.DID{}, publicKey)
		doc.AddAuthenticationMethod(vm)
		assert.Equal(t, vm, doc.Authentication[0].VerificationMethod)
		assert.Equal(t, vm, doc.VerificationMethod[0])
		err := updater.RemoveVerificationMethod(*id123Method, doc)
		if !assert.NoError(t, err) {
			return
		}
		assert.Empty(t, doc.Authentication)
		assert.Empty(t, doc.VerificationMethod)
	})

	t.Run("trying to remove an unknown verificationMethod", func(t *testing.T) {
		doc := &did.Document{}
		err := updater.RemoveVerificationMethod(*id123Method, doc)
		assert.EqualError(t, err, "verificationMethod not found in document")
	})
}

func TestNutsDocUpdater_CreateNewAuthenticationMethodForDocument(t *testing.T) {
	id123, _ := did.ParseDID("did:nuts:123")
	id123Method, _ := did.ParseDID("did:nuts:123#method-1")

	keyCreator := &mockKeyCreator{
		t:      t,
		jwkStr: jwkString,
	}

	updater := NutsDocUpdater{keyCreator: keyCreator}

	t.Run("ok - rotating an existing key", func(t *testing.T) {
		// Prepare a document with an authenticationMethod:
		document := &did.Document{ID: *id123}
		keyPair, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		vMethod, err := did.NewVerificationMethod(*id123Method, ssi.JsonWebKey2020, did.DID{}, keyPair.PublicKey)
		if !assert.NoError(t, err) {
			return
		}
		document.AddAuthenticationMethod(vMethod)
		assert.Equal(t, document.Authentication[0].ID, vMethod.ID)

		err = updater.CreateNewAuthenticationMethodForDocument(document)
		if !assert.NoError(t, err) {
			return
		}

		assert.Len(t, document.Authentication, 2)
		assert.Equal(t, vMethod.ID.String(), document.Authentication[0].ID.String())
		assert.Equal(t, "did:nuts:123#J9O6wvqtYOVwjc8JtZ4aodRdbPv_IKAjLkEq9uHlDdE", document.Authentication[1].ID.String())
	})

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
