package dag

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"github.com/golang/mock/gomock"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestDocumentSignatureVerifier(t *testing.T) {
	t.Run("embedded JWK, sign -> verify", func(t *testing.T) {
		err := NewDocumentSignatureVerifier(nil).Verify(CreateTestDocumentWithJWK(1))
		assert.NoError(t, err)
	})
	t.Run("embedded JWK, sign -> marshal -> unmarshal -> verify", func(t *testing.T) {
		expected, _ := ParseDocument(CreateTestDocumentWithJWK(1).Data())
		err := NewDocumentSignatureVerifier(nil).Verify(expected)
		assert.NoError(t, err)
	})
	t.Run("referral with key ID", func(t *testing.T) {
		document, _, publicKey := CreateTestDocument(1)
		expected, _ := ParseDocument(document.Data())
		err := NewDocumentSignatureVerifier(&crypto.StaticKeyResolver{Key: publicKey}).Verify(expected)
		assert.NoError(t, err)
	})
	t.Run("wrong key", func(t *testing.T) {
		attackerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		document, _, _ := CreateTestDocument(1)
		expected, _ := ParseDocument(document.Data())
		err := NewDocumentSignatureVerifier(&crypto.StaticKeyResolver{Key: attackerKey.Public()}).Verify(expected)
		assert.EqualError(t, err, "failed to verify message: failed to verify signature using ecdsa")
	})
	t.Run("key type is incorrect", func(t *testing.T) {
		d, _, _ := CreateTestDocument(1)
		document := d.(*document)
		document.signingKey = jwk.NewSymmetricKey()
		err := NewDocumentSignatureVerifier(nil).Verify(document)
		assert.EqualError(t, err, "failed to verify message: invalid key type []uint8. *ecdsa.PublicKey is required")
	})
	t.Run("unable to derive key from JWK", func(t *testing.T) {
		d, _, _ := CreateTestDocument(1)
		document := d.(*document)
		document.signingKey = jwk.NewOKPPublicKey()
		err := NewDocumentSignatureVerifier(nil).Verify(document)
		assert.EqualError(t, err, "failed to build public key: invalid curve algorithm P-invalid")
	})
	t.Run("unable to resolve key", func(t *testing.T) {
		d, _, _ := CreateTestDocument(1)
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		keyResolver := crypto.NewMockKeyResolver(ctrl)
		keyResolver.EXPECT().GetPublicKey(gomock.Any(), gomock.Any()).Return(nil, errors.New("failed"))
		err := NewDocumentSignatureVerifier(keyResolver).Verify(d)
		assert.Contains(t, err.Error(), "failed")
	})
}
