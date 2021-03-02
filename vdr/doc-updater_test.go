package vdr

import (
	"testing"

	"github.com/nuts-foundation/go-did"
	"github.com/stretchr/testify/assert"
)

func Test_newNamingFnForExistingDID(t *testing.T) {
	t.Run("it creates a new did", func(t *testing.T) {

		existingDID, _ := did.ParseDID("did:nuts:123")
		fn := newNamingFnForExistingDID(*existingDID)
		assert.NotNil(t, fn)

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
}

func TestNutsDocUpdater_RemoveVerificationMethod(t *testing.T) {
	id123, _ := did.ParseDID("did:nuts:123")
	id123Method, _ := did.ParseDID("did:nuts:123#method-1")
	updater := NutsDocUpdater{}

	t.Run("ok", func(t *testing.T) {
		doc := &did.Document{ID: *id123}
		publicKey, _ := jwkToPublicKey(t, jwkString)
		vm, _ := did.NewVerificationMethod(*id123Method, did.JsonWebKey2020, did.DID{}, publicKey)
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
