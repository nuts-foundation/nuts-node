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
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/assert"

	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
)

// mockKeyCreator can create new keys based on a predefined key
type mockKeyCreator struct {
	kid string
}

// New uses a predefined ECDSA key and calls the namingFunc to get the kid
func (m *mockKeyCreator) New(namingFunc nutsCrypto.KIDNamingFunc) (nutsCrypto.Key, error) {
	return nutsCrypto.NewTestKey(m.kid), nil
}

var kid = "did:nuts:ARRW2e42qyVjQZiACk4Up3mzpshZdJBDBPWsuFQPcDiS#J9O6wvqtYOVwjc8JtZ4aodRdbPv_IKAjLkEq9uHlDdE"
var jwkString = `{"crv":"P-256","kid":"did:nuts:ARRW2e42qyVjQZiACk4Up3mzpshZdJBDBPWsuFQPcDiS#J9O6wvqtYOVwjc8JtZ4aodRdbPv_IKAjLkEq9uHlDdE","kty":"EC","x":"Qn6xbZtOYFoLO2qMEAczcau9uGGWwa1bT+7JmAVLtg4=","y":"d20dD0qlT+d1djVpAfrfsAfKOUxKwKkn1zqFSIuJ398="},"type":"JsonWebKey2020"}`

func TestDefaultCreationOptions(t *testing.T) {
	ops := DefaultCreationOptions()

	assert.True(t, ops.AssertionMethod)
	assert.False(t, ops.Authentication)
	assert.False(t, ops.CapabilityDelegation)
	assert.True(t, ops.CapabilityInvocation)
	assert.False(t, ops.KeyAgreement)
	assert.True(t, ops.SelfControl)
	assert.Empty(t, ops.Controllers)
}

func TestCreator_Create(t *testing.T) {
	defaultOptions := DefaultCreationOptions()

	t.Run("ok", func(t *testing.T) {
		kc := &mockKeyCreator{
			kid: kid,
		}
		creator := Creator{KeyStore: kc}
		t.Run("defaults", func(t *testing.T) {
			doc, key, err := creator.Create(defaultOptions)
			assert.NoError(t, err, "create should not return an error")
			assert.NotNil(t, doc, "create should return a document")
			assert.NotNil(t, key, "create should return a Key")
			assert.Equal(t, "did:nuts:ARRW2e42qyVjQZiACk4Up3mzpshZdJBDBPWsuFQPcDiS", doc.ID.String(), "the DID Doc should have the expected id")
			assert.Len(t, doc.VerificationMethod, 1, "it should have one verificationMethod")
			assert.Equal(t, "did:nuts:ARRW2e42qyVjQZiACk4Up3mzpshZdJBDBPWsuFQPcDiS#J9O6wvqtYOVwjc8JtZ4aodRdbPv_IKAjLkEq9uHlDdE", doc.VerificationMethod[0].ID.String(),
				"verificationMethod should have the correct id")
			assert.Len(t, doc.CapabilityInvocation, 1, "it should have 1 CapabilityInvocation")
			assert.Equal(t, doc.CapabilityInvocation[0].VerificationMethod, doc.VerificationMethod[0], "the assertionMethod should be a pointer to the verificationMethod")
			assert.Len(t, doc.AssertionMethod, 1, "it should have 1 AssertionMethod")
		})

		t.Run("all keys", func(t *testing.T) {
			ops := types.DIDCreationOptions{
				AssertionMethod:      true,
				Authentication:       true,
				CapabilityDelegation: true,
				CapabilityInvocation: true,
				KeyAgreement:         true,
				SelfControl:          true,
			}
			doc, _, err := creator.Create(ops)

			if !assert.NoError(t, err) {
				return
			}

			assert.Len(t, doc.AssertionMethod, 1)
			assert.Len(t, doc.Authentication, 1)
			assert.Len(t, doc.CapabilityDelegation, 1)
			assert.Len(t, doc.CapabilityInvocation, 1)
			assert.Len(t, doc.KeyAgreement, 1)
		})

		t.Run("extra controller", func(t *testing.T) {
			c, _ := did.ParseDID("did:nuts:controller")
			ops := types.DIDCreationOptions{
				AssertionMethod:      true,
				CapabilityInvocation: true,
				SelfControl:          true,
				Controllers:          []did.DID{*c},
			}
			doc, _, err := creator.Create(ops)

			if !assert.NoError(t, err) {
				return
			}

			assert.Len(t, doc.Controller, 2)
		})

		t.Run("using ephemeral key creates different keys for assertion and DID", func(t *testing.T) {
			ops := types.DIDCreationOptions{
				AssertionMethod:      true,
				Authentication:       false,
				CapabilityDelegation: false,
				CapabilityInvocation: false,
				KeyAgreement:         false,
				SelfControl:          false,
			}
			doc, _, err := creator.Create(ops)

			if !assert.NoError(t, err) {
				return
			}

			assert.Len(t, doc.CapabilityInvocation, 0)
			assert.Len(t, doc.VerificationMethod, 1)
			assert.Len(t, doc.AssertionMethod, 1)

			keyID := doc.VerificationMethod[0].ID
			keyID.Fragment = ""

			assert.NotEqual(t, doc.ID, keyID)
		})
	})

	t.Run("error - invalid combination", func(t *testing.T) {
		ops := types.DIDCreationOptions{
			CapabilityInvocation: false,
			SelfControl:          true,
		}
		kc := &mockKeyCreator{
			kid: kid,
		}
		creator := Creator{KeyStore: kc}
		_, _, err := creator.Create(ops)

		assert.Equal(t, ErrInvalidOptions, err)
	})

	t.Run("error - failed to create key for selfcontrol", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockKeyStore := nutsCrypto.NewMockKeyStore(ctrl)
		defer ctrl.Finish()
		creator := Creator{KeyStore: mockKeyStore}
		mockKeyStore.EXPECT().New(gomock.Any()).Return(nil, errors.New("b00m!"))

		_, _, err := creator.Create(DefaultCreationOptions())

		if !assert.Error(t, err) {
			return
		}
		assert.EqualError(t, err, "b00m!")
	})

	t.Run("error - failed to create key for other verification method", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockKeyStore := nutsCrypto.NewMockKeyStore(ctrl)
		defer ctrl.Finish()
		creator := Creator{KeyStore: mockKeyStore}
		ops := types.DIDCreationOptions{
			AssertionMethod:      true,
			Authentication:       false,
			CapabilityDelegation: false,
			CapabilityInvocation: false,
			KeyAgreement:         false,
			SelfControl:          false,
		}
		mockKeyStore.EXPECT().New(gomock.Any()).Return(nil, errors.New("b00m!"))

		_, _, err := creator.Create(ops)

		if !assert.Error(t, err) {
			return
		}
		assert.EqualError(t, err, "b00m!")
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

	t.Run("ok - predefined key", func(t *testing.T) {
		pub, err := jwkToPublicKey(t, jwkString)
		if assert.NoError(t, err) {
			return
		}

		keyID, err := didKIDNamingFunc(pub)
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, keyID, kid, keyID)
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
	return &rawKey, nil
}
