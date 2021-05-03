package dag

import (
	"errors"
	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_defaultPowerOnSelfTest_perform(t *testing.T) {
	t.Run("ok (no error)", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		graph := NewMockDAG(ctrl)
		publisher := NewMockPublisher(ctrl)
		signatureVerifier := NewMockTransactionSignatureVerifier(ctrl)

		publisher.EXPECT().Subscribe(AnyPayloadType, gomock.Any())
		graph.EXPECT().FindBetween(MinTime(), MaxTime())
		post := NewVerifier(graph, publisher, signatureVerifier)
		err := post.Verify()
		assert.NoError(t, err)
	})
	t.Run("ok (already finished)", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		graph := NewMockDAG(ctrl)
		publisher := NewMockPublisher(ctrl)
		signatureVerifier := NewMockTransactionSignatureVerifier(ctrl)

		publisher.EXPECT().Subscribe(AnyPayloadType, gomock.Any())
		post := NewVerifier(graph, publisher, signatureVerifier).(*defaultVerifier)
		post.finished = true
		err := post.Verify()
		assert.NoError(t, err)
	})
	t.Run("test fails", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		graph := NewMockDAG(ctrl)
		publisher := NewMockPublisher(ctrl)
		signatureVerifier := NewMockTransactionSignatureVerifier(ctrl)

		publisher.EXPECT().Subscribe(AnyPayloadType, gomock.Any())
		post := NewVerifier(graph, publisher, signatureVerifier).(*defaultVerifier)
		post.failure = errors.New("failed")
		err := post.Verify()
		assert.EqualError(t, err, "DAG verification failed: failed")
	})
}

func Test_defaultPowerOnSelfTest_verifyTransactions(t *testing.T) {
	prev := hash.SHA256Sum([]byte{1, 2, 3})
	t.Run("ok - prev is present", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		graph := NewMockDAG(ctrl)
		publisher := NewMockPublisher(ctrl)
		signatureVerifier := NewMockTransactionSignatureVerifier(ctrl)

		publisher.EXPECT().Subscribe(AnyPayloadType, gomock.Any())
		graph.EXPECT().IsPresent(prev).Return(true, nil)
		tx, _, _ := CreateTestTransaction(1, prev)
		graph.EXPECT().FindBetween(MinTime(), MaxTime()).Return([]Transaction{tx}, nil)
		post := NewVerifier(graph, publisher, signatureVerifier).(*defaultVerifier)
		err := post.verifyTransactions()
		assert.NoError(t, err)
	})
	t.Run("failed - prev not present", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		graph := NewMockDAG(ctrl)
		publisher := NewMockPublisher(ctrl)
		signatureVerifier := NewMockTransactionSignatureVerifier(ctrl)

		publisher.EXPECT().Subscribe(AnyPayloadType, gomock.Any())
		graph.EXPECT().IsPresent(prev).Return(false, nil)
		tx, _, _ := CreateTestTransaction(1, prev)
		graph.EXPECT().FindBetween(MinTime(), MaxTime()).Return([]Transaction{tx}, nil)
		post := NewVerifier(graph, publisher, signatureVerifier).(*defaultVerifier)
		err := post.verifyTransactions()
		assert.Contains(t, err.Error(), "transaction is referring to non-existing previous transaction")
	})
}

func Test_defaultPowerOnSelfTest_verifyTransactionSignature(t *testing.T) {
	t.Run("test fails", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		graph := NewMockDAG(ctrl)
		publisher := NewMockPublisher(ctrl)
		signatureVerifier := NewMockTransactionSignatureVerifier(ctrl)

		publisher.EXPECT().Subscribe(AnyPayloadType, gomock.Any())
		tx, _, _ := CreateTestTransaction(1)
		signatureVerifier.EXPECT().Verify(tx).Return(errors.New("signature invalid"))
		post := NewVerifier(graph, publisher, signatureVerifier).(*defaultVerifier)
		err := post.verifyTransactionSignature(tx, nil)
		assert.NoError(t, err)
	})
	t.Run("already finished", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		graph := NewMockDAG(ctrl)
		publisher := NewMockPublisher(ctrl)
		signatureVerifier := NewMockTransactionSignatureVerifier(ctrl)

		publisher.EXPECT().Subscribe(AnyPayloadType, gomock.Any())
		tx, _, _ := CreateTestTransaction(1)
		post := NewVerifier(graph, publisher, signatureVerifier).(*defaultVerifier)
		post.finished = true
		err := post.verifyTransactionSignature(tx, nil)
		assert.NoError(t, err)
	})
}
