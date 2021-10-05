package dag

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/vdr/doc"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/assert"
)

func Test_PrevTransactionVerifier(t *testing.T) {
	prev := hash.SHA256Sum([]byte{1, 2, 3})
	t.Run("ok - prev is present", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.Background()
		graph := NewMockDAG(ctrl)
		graph.EXPECT().IsPresent(ctx, prev).Return(true, nil)
		tx, _, _ := CreateTestTransaction(1, prev)
		err := NewPrevTransactionsVerifier()(ctx, tx, graph)
		assert.NoError(t, err)
	})
	t.Run("failed - prev not present", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		ctx := context.Background()
		graph := NewMockDAG(ctrl)
		graph.EXPECT().IsPresent(ctx, prev).Return(false, nil)
		tx, _, _ := CreateTestTransaction(1, prev)
		err := NewPrevTransactionsVerifier()(ctx, tx, graph)
		assert.Contains(t, err.Error(), "transaction is referring to non-existing previous transaction")
	})
}

func TestTransactionSignatureVerifier(t *testing.T) {
	t.Run("embedded JWK, sign -> verify", func(t *testing.T) {
		err := NewTransactionSignatureVerifier(nil)(context.Background(), CreateTestTransactionWithJWK(1), nil)
		assert.NoError(t, err)
	})
	t.Run("embedded JWK, sign -> marshal -> unmarshal -> verify", func(t *testing.T) {
		expected, _ := ParseTransaction(CreateTestTransactionWithJWK(1).Data())
		err := NewTransactionSignatureVerifier(nil)(context.Background(), expected, nil)
		assert.NoError(t, err)
	})
	t.Run("referral with key ID", func(t *testing.T) {
		transaction, _, publicKey := CreateTestTransaction(1)
		expected, _ := ParseTransaction(transaction.Data())
		err := NewTransactionSignatureVerifier(&doc.StaticKeyResolver{Key: publicKey})(context.Background(), expected, nil)
		assert.NoError(t, err)
	})
	t.Run("wrong key", func(t *testing.T) {
		attackerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		transaction, _, _ := CreateTestTransaction(1)
		expected, _ := ParseTransaction(transaction.Data())
		err := NewTransactionSignatureVerifier(&doc.StaticKeyResolver{Key: attackerKey.Public()})(context.Background(), expected, nil)
		assert.EqualError(t, err, "failed to verify message: failed to verify signature using ecdsa")
	})
	t.Run("key type is incorrect", func(t *testing.T) {
		d, _, _ := CreateTestTransaction(1)
		tx := d.(*transaction)
		tx.signingKey = jwk.NewSymmetricKey()
		err := NewTransactionSignatureVerifier(nil)(context.Background(), tx, nil)
		assert.EqualError(t, err, "failed to verify message: failed to retrieve ecdsa.PublicKey out of []uint8: expected ecdsa.PublicKey or *ecdsa.PublicKey, got []uint8")
	})
	t.Run("unable to derive key from JWK", func(t *testing.T) {
		d, _, _ := CreateTestTransaction(1)
		transaction := d.(*transaction)
		transaction.signingKey = jwk.NewOKPPublicKey()
		err := NewTransactionSignatureVerifier(nil)(context.Background(), transaction, nil)
		assert.EqualError(t, err, "failed to build public key: invalid curve algorithm P-invalid")
	})
	t.Run("unable to resolve key by time", func(t *testing.T) {
		aWhileBack := didDocumentResolveEPoch.Add(-1 * time.Second)
		d := CreateSignedTestTransaction(1, aWhileBack, "foo/bar", false)
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		keyResolver := types.NewMockKeyResolver(ctrl)
		keyResolver.EXPECT().ResolvePublicKey(gomock.Any(), gomock.Any()).Return(nil, errors.New("failed"))
		err := NewTransactionSignatureVerifier(keyResolver)(context.Background(), d, nil)
		if !assert.Error(t, err) {
			return
		}
		assert.Contains(t, err.Error(), "unable to verify transaction signature, can't resolve key by signing time")
		assert.Contains(t, err.Error(), "failed")
	})
	t.Run("unable to resolve key by hash", func(t *testing.T) {
		after := didDocumentResolveEPoch.Add(1 * time.Second)
		d := CreateSignedTestTransaction(1, after, "foo/bar", false)
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		keyResolver := types.NewMockKeyResolver(ctrl)
		keyResolver.EXPECT().ResolvePublicKeyFromOriginatingTransaction(gomock.Any(), d.Ref()).Return(nil, errors.New("failed"))
		err := NewTransactionSignatureVerifier(keyResolver)(context.Background(), d, nil)
		if !assert.Error(t, err) {
			return
		}
		assert.Contains(t, err.Error(), "unable to verify transaction signature, can't resolve key by TX ref")
		assert.Contains(t, err.Error(), "failed")
	})
}

func TestSigningTimeVerifier(t *testing.T) {
	t.Run("signed now", func(t *testing.T) {
		err := NewSigningTimeVerifier()(CreateSignedTestTransaction(1, time.Now(), "test/test", true), nil)
		assert.NoError(t, err)
	})
	t.Run("signed in history", func(t *testing.T) {
		aWhileBack := time.Now().AddDate(-1, 0, 0)
		err := NewSigningTimeVerifier()(CreateSignedTestTransaction(1, aWhileBack, "test/test", true), nil)
		assert.NoError(t, err)
	})
	t.Run("signed a few hours in the future", func(t *testing.T) {
		soon := time.Now().Add(time.Hour * 2)
		err := NewSigningTimeVerifier()(CreateSignedTestTransaction(1, soon, "test/test", true), nil)
		assert.NoError(t, err)
	})
	t.Run("error - signed a day in the future", func(t *testing.T) {
		later := time.Now().Add(time.Hour*24 + time.Minute)
		err := NewSigningTimeVerifier()(CreateSignedTestTransaction(1, later, "test/test", true), nil)
		assert.Error(t, err)
	})
}
