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

package dag

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestEncryptPal(t *testing.T) {
	pA, _ := did.ParseDID("did:nuts:A")
	pB, _ := did.ParseDID("did:nuts:B")
	pkA, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pkB, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	t.Run("roundtrip", func(t *testing.T) {
		// The "local" node is participant B, so we should be able to decrypt it with B's private key

		// Encrypt
		ctrl := gomock.NewController(t)
		keyResolver := types.NewMockKeyResolver(ctrl)
		keyResolver.EXPECT().ResolveKeyAgreementKey(*pA).Return(pkA.Public(), nil)
		keyResolver.EXPECT().ResolveKeyAgreementKey(*pB).Return(pkB.Public(), nil)
		expected := PAL{*pA, *pB}
		pal, err := expected.Encrypt(keyResolver)
		if !assert.NoError(t, err) {
			return
		}

		// Decrypt
		keyStore := crypto.NewTestCryptoInstance()
		keyStore.Storage.SavePrivateKey("kid-B", pkB)
		actual, err := pal.Decrypt([]string{"kid-B"}, keyStore)
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, expected, actual)
	})
	t.Run("ok - empty input yields empty output", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		keyResolver := types.NewMockKeyResolver(ctrl)
		pal, err := PAL{}.Encrypt(keyResolver)
		assert.Nil(t, pal)
		assert.NoError(t, err)
	})
	t.Run("error - keyAgreement key type is not supported", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		keyResolver := types.NewMockKeyResolver(ctrl)
		keyResolver.EXPECT().ResolveKeyAgreementKey(*pA).Return(&rsa.PublicKey{}, nil)
		pal, err := PAL{*pA}.Encrypt(keyResolver)
		assert.Nil(t, pal)
		assert.EqualError(t, err, "resolved keyAgreement key is not an elliptic curve key (recipient=did:nuts:A)")
	})
	t.Run("error - no keyAgreements", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		keyResolver := types.NewMockKeyResolver(ctrl)
		keyResolver.EXPECT().ResolveKeyAgreementKey(*pA).Return(nil, types.ErrKeyNotFound)
		pal, err := PAL{*pA}.Encrypt(keyResolver)
		assert.Nil(t, pal)
		assert.EqualError(t, err, "unable to resolve keyAgreement key (recipient=did:nuts:A): key not found in DID document")
	})
}

func TestDecryptPal(t *testing.T) {
	pk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	t.Run("ok - not decryptable, no matching private keys", func(t *testing.T) {
		keyStore := crypto.NewTestCryptoInstance()
		keyStore.Storage.SavePrivateKey("kid-1", pk)
		actual, err := EncryptedPAL{{1, 2}, {3}}.Decrypt([]string{"kid-1"}, keyStore)
		assert.Nil(t, actual)
		assert.NoError(t, err)
	})
	t.Run("error - private key is missing", func(t *testing.T) {
		keyStore := crypto.NewTestCryptoInstance()
		actual, err := EncryptedPAL{{1, 2}, {3}}.Decrypt([]string{"kid-1"}, keyStore)
		assert.Nil(t, actual)
		assert.EqualError(t, err, "private key of DID keyAgreement not found (kid=kid-1)")
	})
	t.Run("error - invalid DID in decrypted PAL", func(t *testing.T) {
		keyStore := crypto.NewTestCryptoInstance()
		keyStore.Storage.SavePrivateKey("kid-1", pk)
		cipherText, _ := crypto.EciesEncrypt(pk.Public().(*ecdsa.PublicKey), []byte{1, 2, 3})
		actual, err := EncryptedPAL{cipherText}.Decrypt([]string{"kid-1"}, keyStore)
		assert.Nil(t, actual)
		assert.EqualError(t, err, "invalid participant (did=\x01\x02\x03): invalid DID: input length is less than 7")
	})
}
