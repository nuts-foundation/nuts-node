package dag

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/stretchr/testify/assert"
)

func TestTransactionSignatureVerifier(t *testing.T) {
	t.Run("embedded JWK, sign -> verify", func(t *testing.T) {
		err := NewTransactionSignatureVerifier(nil).Verify(CreateTestTransactionWithJWK(1))
		assert.NoError(t, err)
	})
	t.Run("embedded JWK, sign -> marshal -> unmarshal -> verify", func(t *testing.T) {
		expected, _ := ParseTransaction(CreateTestTransactionWithJWK(1).Data())
		err := NewTransactionSignatureVerifier(nil).Verify(expected)
		assert.NoError(t, err)
	})
	t.Run("referral with key ID", func(t *testing.T) {
		transaction, _, publicKey := CreateTestTransaction(1)
		expected, _ := ParseTransaction(transaction.Data())
		err := NewTransactionSignatureVerifier(&crypto.StaticKeyResolver{Key: publicKey}).Verify(expected)
		assert.NoError(t, err)
	})
	t.Run("wrong key", func(t *testing.T) {
		attackerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		transaction, _, _ := CreateTestTransaction(1)
		expected, _ := ParseTransaction(transaction.Data())
		err := NewTransactionSignatureVerifier(&crypto.StaticKeyResolver{Key: attackerKey.Public()}).Verify(expected)
		assert.EqualError(t, err, "failed to verify message: failed to verify signature using ecdsa")
	})
	t.Run("key type is incorrect", func(t *testing.T) {
		d, _, _ := CreateTestTransaction(1)
		tx := d.(*transaction)
		tx.signingKey = jwk.NewSymmetricKey()
		err := NewTransactionSignatureVerifier(nil).Verify(tx)
		assert.EqualError(t, err, "failed to verify message: failed to retrieve ecdsa.PublicKey out of []uint8: expected ecdsa.PublicKey or *ecdsa.PublicKey, got []uint8")
	})
	t.Run("unable to derive key from JWK", func(t *testing.T) {
		d, _, _ := CreateTestTransaction(1)
		transaction := d.(*transaction)
		transaction.signingKey = jwk.NewOKPPublicKey()
		err := NewTransactionSignatureVerifier(nil).Verify(transaction)
		assert.EqualError(t, err, "failed to build public key: invalid curve algorithm P-invalid")
	})
	t.Run("unable to resolve key", func(t *testing.T) {
		d, _, _ := CreateTestTransaction(1)
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		keyResolver := crypto.NewMockKeyResolver(ctrl)
		keyResolver.EXPECT().GetPublicKey(gomock.Any(), gomock.Any()).Return(nil, errors.New("failed"))
		err := NewTransactionSignatureVerifier(keyResolver).Verify(d)
		assert.Contains(t, err.Error(), "failed")
	})
}
