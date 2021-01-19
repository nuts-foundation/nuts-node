package vdr

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"

	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
)

type mockKeyCreator struct {
	called bool
}

func (m *mockKeyCreator) New(namingFunc nutsCrypto.KidNamingFunc) (crypto.PublicKey, string, error) {
	m.called = true
	keyPair, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}
	kid, _ := namingFunc(keyPair.Public())
	return keyPair.Public(), kid, nil
}

func TestDocCreator_Create(t *testing.T) {
	kc := &mockKeyCreator{}
	sut := DocCreator{keyCreator: kc}
	t.Run("ok", func(t *testing.T) {
		doc, err := sut.Create()
		assert.NoError(t, err)
		assert.NotNil(t, doc)
		assert.True(t, kc.called)
		didDocJson, _ := json.Marshal(doc)
		t.Log(string(didDocJson))
	})
}
