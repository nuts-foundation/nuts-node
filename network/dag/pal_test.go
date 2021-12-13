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
		expected := []did.DID{*pA, *pB}
		pal, err := EncryptPal(keyResolver, expected)
		if !assert.NoError(t, err) {
			return
		}

		// Decrypt
		keyStore := crypto.NewTestCryptoInstance("")
		keyStore.Storage.SavePrivateKey("kid-B", pkB)
		actual, err := DecryptPal(pal, []string{"kid-B"}, keyStore)
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, expected, actual)
	})
	t.Run("ok - empty input yields empty output", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		keyResolver := types.NewMockKeyResolver(ctrl)
		pal, err := EncryptPal(keyResolver, []did.DID{})
		assert.Nil(t, pal)
		assert.NoError(t, err)
	})
	t.Run("error - keyAgreement key type is not supported", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		keyResolver := types.NewMockKeyResolver(ctrl)
		keyResolver.EXPECT().ResolveKeyAgreementKey(*pA).Return(&rsa.PublicKey{}, nil)
		pal, err := EncryptPal(keyResolver, []did.DID{*pA})
		assert.Nil(t, pal)
		assert.EqualError(t, err, "resolved keyAgreement key is not an elliptic curve key (recipient=did:nuts:A)")
	})
	t.Run("error - no keyAgreements", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		keyResolver := types.NewMockKeyResolver(ctrl)
		keyResolver.EXPECT().ResolveKeyAgreementKey(*pA).Return(nil, types.ErrKeyNotFound)
		pal, err := EncryptPal(keyResolver, []did.DID{*pA})
		assert.Nil(t, pal)
		assert.EqualError(t, err, "unable to resolve keyAgreement key (recipient=did:nuts:A): key not found in DID document")
	})
}

func TestDecryptPal(t *testing.T) {
	pk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	t.Run("ok - not decryptable, no matching private keys", func(t *testing.T) {
		keyStore := crypto.NewTestCryptoInstance("")
		keyStore.Storage.SavePrivateKey("kid-1", pk)
		actual, err := DecryptPal([][]byte{{1, 2}, {3}}, []string{"kid-1"}, keyStore)
		assert.Nil(t, actual)
		assert.NoError(t, err)
	})
	t.Run("error - private key is missing", func(t *testing.T) {
		keyStore := crypto.NewTestCryptoInstance("")
		actual, err := DecryptPal([][]byte{{1, 2}, {3}}, []string{"kid-1"}, keyStore)
		assert.Nil(t, actual)
		assert.EqualError(t, err, "private key of DID keyAgreement not found (kid=kid-1)")
	})
	t.Run("error - invalid DID in decrypted PAL", func(t *testing.T) {
		keyStore := crypto.NewTestCryptoInstance("")
		keyStore.Storage.SavePrivateKey("kid-1", pk)
		cipherText, _ := crypto.EciesEncrypt(pk.Public().(*ecdsa.PublicKey), []byte{1, 2, 3})
		actual, err := DecryptPal([][]byte{cipherText}, []string{"kid-1"}, keyStore)
		assert.Nil(t, actual)
		assert.EqualError(t, err, "invalid participant (did=\x01\x02\x03): invalid DID: input length is less than 7")
	})
}
