package vdr

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"github.com/golang/mock/gomock"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/nuts-foundation/go-did"
	"testing"

	"github.com/lestrrat-go/jwx/jwk"
	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/stretchr/testify/assert"
)

// mockKeyCreator can create new keys based on a predefined key
type mockKeyCreator struct {
	// jwkStr hold the predefined key in a json web key string
	jwkStr string
	t      *testing.T
}

// New uses a predefined ECDSA key and calls the namingFunc to get the kid
func (m *mockKeyCreator) New(namingFunc nutsCrypto.KIDNamingFunc) (crypto.PublicKey, string, error) {
	rawKey, err := jwkToPublicKey(m.t, m.jwkStr)
	if err != nil {
		return nil, "", err
	}
	kid, err := namingFunc(rawKey)
	if err != nil {
		return nil, "", err
	}
	return rawKey, kid, nil
}

var jwkString = `{"crv":"P-256","kid":"did:nuts:ARRW2e42qyVjQZiACk4Up3mzpshZdJBDBPWsuFQPcDiS#J9O6wvqtYOVwjc8JtZ4aodRdbPv_IKAjLkEq9uHlDdE","kty":"EC","x":"Qn6xbZtOYFoLO2qMEAczcau9uGGWwa1bT+7JmAVLtg4=","y":"d20dD0qlT+d1djVpAfrfsAfKOUxKwKkn1zqFSIuJ398="},"type":"JsonWebKey2020"}`

func TestDocCreator_Create(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		kc := &mockKeyCreator{
			t:      t,
			jwkStr: jwkString,
		}
		sut := NutsDocCreator{keyCreator: kc}
		t.Run("ok", func(t *testing.T) {
			doc, err := sut.Create()
			assert.NoError(t, err)
			assert.NotNil(t, doc)

			assert.Equal(t, "did:nuts:ARRW2e42qyVjQZiACk4Up3mzpshZdJBDBPWsuFQPcDiS", doc.ID.String())

			assert.Len(t, doc.Controller, 1)
			assert.Equal(t, doc.ID.String(), doc.Controller[0].String())

			assert.Len(t, doc.VerificationMethod, 1)
			assert.Equal(t, "did:nuts:ARRW2e42qyVjQZiACk4Up3mzpshZdJBDBPWsuFQPcDiS#J9O6wvqtYOVwjc8JtZ4aodRdbPv_IKAjLkEq9uHlDdE", doc.VerificationMethod[0].ID.String())

			assert.Len(t, doc.Authentication, 1)
			assert.Equal(t, doc.Authentication[0].VerificationMethod, doc.VerificationMethod[0])

			assert.Empty(t, doc.AssertionMethod)
		})
	})
	t.Run("invalid key ID", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		creator := nutsCrypto.NewMockKeyCreator(ctrl)
		creator.EXPECT().New(gomock.Any()).Return(nil, "foobar", nil)
		sut := NutsDocCreator{keyCreator: creator}
		doc, err := sut.Create()
		assert.EqualError(t, err, "input length is less than 7")
		assert.Nil(t, doc)
	})
	t.Run("invalid verification method", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		creator := nutsCrypto.NewMockKeyCreator(ctrl)
		creator.EXPECT().New(gomock.Any()).Return("asdasdsad", "did:nuts:ARRW2e42qyVjQZiACk4Up3mzpshZdJBDBPWsuFQPcDiS#J9O6wvqtYOVwjc8JtZ4aodRdbPv_IKAjLkEq9uHlDdE", nil)
		sut := NutsDocCreator{keyCreator: creator}
		doc, err := sut.Create()
		assert.EqualError(t, err, "invalid key type 'string' for jwk.New")
		assert.Nil(t, doc)
	})
}

func Test_didKidNamingFunc(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if assert.NoError(t, err) {
			return
		}

		keyID, err := didKIDNamingFunc(privateKey.PublicKey)
		if !assert.NoError(t, err) {
			return
		}
		assert.NotEmpty(t, keyID)
		assert.Contains(t, keyID, "did:nuts")
	})

	t.Run("nok - wrong key type", func(t *testing.T) {
		privateKey := rsa.PrivateKey{}
		keyID, err := didKIDNamingFunc(privateKey.PublicKey)
		if !assert.Error(t, err) {
			return
		}
		assert.Equal(t, "could not generate kid: invalid key type", err.Error())
		assert.Empty(t, keyID)

	})

	t.Run("nok - empty key", func(t *testing.T) {
		pubKey := &ecdsa.PublicKey{}
		keyID, err := didKIDNamingFunc(pubKey)
		assert.Error(t, err)
		assert.Equal(t, "could not generate kid: empty key curve", err.Error())
		assert.Empty(t, keyID)
	})
}

func jwkToPublicKey(t *testing.T, jwkStr string) (crypto.PublicKey, error) {
	t.Helper()
	keySet, err := jwk.ParseString(jwkStr)
	if !assert.NoError(t, err) {
		return nil, err
	}
	key, _ := keySet.Get(0)
	var rawKey crypto.PublicKey
	if err = key.Raw(&rawKey); err != nil {
		return nil, err
	}
	return rawKey, nil
}

func Test_keyToVerificationMethod(t *testing.T) {
	t.Run("invalid key", func(t *testing.T) {
		rawKey, err := jwkToPublicKey(t, jwkString)
		if !assert.NoError(t, err) {
			return
		}
		vm, err := keyToVerificationMethod(rawKey, "keyID")
		assert.Error(t, err)
		assert.Nil(t, vm)
	})
	t.Run("ok", func(t *testing.T) {
		rawKey, err := jwkToPublicKey(t, jwkString)
		if !assert.NoError(t, err) {
			return
		}
		kid, _ := didKIDNamingFunc(rawKey)
		vm, err := keyToVerificationMethod(rawKey, kid)
		assert.NoError(t, err)
		assert.NotNil(t, vm)

		assert.Equal(t, kid, vm.ID.String())
		assert.Equal(t, did.JsonWebKey2020, vm.Type)
		assert.Equal(t, jwa.EllipticCurveAlgorithm("P-256"), vm.PublicKeyJwk["crv"])
	})
}
