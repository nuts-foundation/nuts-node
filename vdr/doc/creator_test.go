/*
 * Nuts node
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

package doc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/golang/mock/gomock"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/stretchr/testify/assert"

	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
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

var kid = "did:nuts:ARRW2e42qyVjQZiACk4Up3mzpshZdJBDBPWsuFQPcDiS#J9O6wvqtYOVwjc8JtZ4aodRdbPv_IKAjLkEq9uHlDdE"
var jwkString = `{"crv":"P-256","kid":"did:nuts:ARRW2e42qyVjQZiACk4Up3mzpshZdJBDBPWsuFQPcDiS#J9O6wvqtYOVwjc8JtZ4aodRdbPv_IKAjLkEq9uHlDdE","kty":"EC","x":"Qn6xbZtOYFoLO2qMEAczcau9uGGWwa1bT+7JmAVLtg4=","y":"d20dD0qlT+d1djVpAfrfsAfKOUxKwKkn1zqFSIuJ398="},"type":"JsonWebKey2020"}`

func TestDocCreator_Create(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		kc := &mockKeyCreator{
			t:      t,
			jwkStr: jwkString,
		}
		sut := Creator{KeyCreator: kc}
		t.Run("ok", func(t *testing.T) {
			doc, err := sut.Create()
			assert.NoError(t, err,
				"create should not return an error")
			assert.NotNil(t, doc,
				"create should return a document")

			assert.Equal(t, "did:nuts:ARRW2e42qyVjQZiACk4Up3mzpshZdJBDBPWsuFQPcDiS", doc.ID.String(),
				"the DID Doc should have the expected id")

			assert.Len(t, doc.VerificationMethod, 1,
				"it should have one verificationMethod")
			assert.Equal(t, "did:nuts:ARRW2e42qyVjQZiACk4Up3mzpshZdJBDBPWsuFQPcDiS#J9O6wvqtYOVwjc8JtZ4aodRdbPv_IKAjLkEq9uHlDdE", doc.VerificationMethod[0].ID.String(),
				"verificationMethod should have the correct id")

			assert.Len(t, doc.CapabilityInvocation, 1,
				"it should have 1 authenticationMethod")
			assert.Equal(t, doc.CapabilityInvocation[0].VerificationMethod, doc.VerificationMethod[0],
				"the assertionMethod should be a pointer to the verificationMethod")

			assert.Empty(t, doc.AssertionMethod,
				"no assertionMethods should been set")
		})
	})
	t.Run("invalid key ID", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		creator := nutsCrypto.NewMockKeyCreator(ctrl)
		creator.EXPECT().New(gomock.Any()).Return(nil, "foobar", nil)
		sut := Creator{KeyCreator: creator}
		doc, err := sut.Create()
		assert.EqualError(t, err, "input length is less than 7")
		assert.Nil(t, doc)
	})
	t.Run("invalid verification method", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		creator := nutsCrypto.NewMockKeyCreator(ctrl)
		creator.EXPECT().New(gomock.Any()).Return("asdasdsad", "did:nuts:ARRW2e42qyVjQZiACk4Up3mzpshZdJBDBPWsuFQPcDiS#J9O6wvqtYOVwjc8JtZ4aodRdbPv_IKAjLkEq9uHlDdE", nil)
		sut := Creator{KeyCreator: creator}
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
