package dag

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"github.com/golang/mock/gomock"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/vdr/doc"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_PrevTransactionVerifier(t *testing.T) {
	prev := hash.SHA256Sum([]byte{1, 2, 3})
	t.Run("ok - prev is present", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		graph := NewMockDAG(ctrl)
		graph.EXPECT().IsPresent(prev).Return(true, nil)
		tx, _, _ := CreateTestTransaction(1, prev)
		post := NewPrevTransactionsVerifier().(*prevTransactionsVerifier)
		err := post.Verify(tx, graph)
		assert.NoError(t, err)
	})
	t.Run("failed - prev not present", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		graph := NewMockDAG(ctrl)
		graph.EXPECT().IsPresent(prev).Return(false, nil)
		tx, _, _ := CreateTestTransaction(1, prev)
		post := NewPrevTransactionsVerifier().(*prevTransactionsVerifier)
		err := post.Verify(tx, graph)
		assert.Contains(t, err.Error(), "transaction is referring to non-existing previous transaction")
	})
}

func TestTransactionSignatureVerifier(t *testing.T) {
	t.Run("embedded JWK, sign -> verify", func(t *testing.T) {
		err := NewTransactionSignatureVerifier(nil).Verify(CreateTestTransactionWithJWK(1), nil)
		assert.NoError(t, err)
	})
	t.Run("embedded JWK, sign -> marshal -> unmarshal -> verify", func(t *testing.T) {
		expected, _ := ParseTransaction(CreateTestTransactionWithJWK(1).Data())
		err := NewTransactionSignatureVerifier(nil).Verify(expected, nil)
		assert.NoError(t, err)
	})
	t.Run("referral with key ID", func(t *testing.T) {
		transaction, _, publicKey := CreateTestTransaction(1)
		expected, _ := ParseTransaction(transaction.Data())
		err := NewTransactionSignatureVerifier(&doc.StaticKeyResolver{Key: publicKey}).Verify(expected, nil)
		assert.NoError(t, err)
	})
	t.Run("wrong key", func(t *testing.T) {
		attackerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		transaction, _, _ := CreateTestTransaction(1)
		expected, _ := ParseTransaction(transaction.Data())
		err := NewTransactionSignatureVerifier(&doc.StaticKeyResolver{Key: attackerKey.Public()}).Verify(expected, nil)
		assert.EqualError(t, err, "failed to verify message: failed to verify signature using ecdsa")
	})
	t.Run("key type is incorrect", func(t *testing.T) {
		d, _, _ := CreateTestTransaction(1)
		tx := d.(*transaction)
		tx.signingKey = jwk.NewSymmetricKey()
		err := NewTransactionSignatureVerifier(nil).Verify(tx, nil)
		assert.EqualError(t, err, "failed to verify message: failed to retrieve ecdsa.PublicKey out of []uint8: expected ecdsa.PublicKey or *ecdsa.PublicKey, got []uint8")
	})
	t.Run("unable to derive key from JWK", func(t *testing.T) {
		d, _, _ := CreateTestTransaction(1)
		transaction := d.(*transaction)
		transaction.signingKey = jwk.NewOKPPublicKey()
		err := NewTransactionSignatureVerifier(nil).Verify(transaction, nil)
		assert.EqualError(t, err, "failed to build public key: invalid curve algorithm P-invalid")
	})
	t.Run("unable to resolve key", func(t *testing.T) {
		d, _, _ := CreateTestTransaction(1)
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		keyResolver := types.NewMockKeyResolver(ctrl)
		keyResolver.EXPECT().ResolvePublicKey(gomock.Any(), gomock.Any()).Return(nil, errors.New("failed"))
		err := NewTransactionSignatureVerifier(keyResolver).Verify(d, nil)
		assert.Contains(t, err.Error(), "failed")
	})
}
