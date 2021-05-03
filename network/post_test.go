package network

import (
	"errors"
	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_defaultPowerOnSelfTest_perform(t *testing.T) {
	t.Run("ok (no error)", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		graph := dag.NewMockDAG(ctrl)
		publisher := dag.NewMockPublisher(ctrl)
		signatureVerifier := dag.NewMockTransactionSignatureVerifier(ctrl)

		publisher.EXPECT().Subscribe(dag.AnyPayloadType, gomock.Any())
		graph.EXPECT().FindBetween(dag.MinTime(), dag.MaxTime())
		post := newPowerOnSelfTest(graph, publisher, signatureVerifier)
		err := post.perform()
		assert.NoError(t, err)
	})
	t.Run("ok (already finished)", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		graph := dag.NewMockDAG(ctrl)
		publisher := dag.NewMockPublisher(ctrl)
		signatureVerifier := dag.NewMockTransactionSignatureVerifier(ctrl)

		publisher.EXPECT().Subscribe(dag.AnyPayloadType, gomock.Any())
		post := newPowerOnSelfTest(graph, publisher, signatureVerifier).(*defaultPowerOnSelfTest)
		post.finished = true
		err := post.perform()
		assert.NoError(t, err)
	})
	t.Run("test fails", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		graph := dag.NewMockDAG(ctrl)
		publisher := dag.NewMockPublisher(ctrl)
		signatureVerifier := dag.NewMockTransactionSignatureVerifier(ctrl)

		publisher.EXPECT().Subscribe(dag.AnyPayloadType, gomock.Any())
		post := newPowerOnSelfTest(graph, publisher, signatureVerifier).(*defaultPowerOnSelfTest)
		post.failure = errors.New("failed")
		err := post.perform()
		assert.EqualError(t, err, "Power-On-Self-Test failed: failed")
	})
}

func Test_defaultPowerOnSelfTest_verifyTransactions(t *testing.T) {
	prev := hash.SHA256Sum([]byte{1, 2, 3})
	t.Run("ok - prev is present", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		graph := dag.NewMockDAG(ctrl)
		publisher := dag.NewMockPublisher(ctrl)
		signatureVerifier := dag.NewMockTransactionSignatureVerifier(ctrl)

		publisher.EXPECT().Subscribe(dag.AnyPayloadType, gomock.Any())
		graph.EXPECT().IsPresent(prev).Return(true, nil)
		tx, _, _ := dag.CreateTestTransaction(1, prev)
		graph.EXPECT().FindBetween(dag.MinTime(), dag.MaxTime()).Return([]dag.Transaction{tx}, nil)
		post := newPowerOnSelfTest(graph, publisher, signatureVerifier).(*defaultPowerOnSelfTest)
		err := post.verifyTransactions()
		assert.NoError(t, err)
	})
	t.Run("failed - prev not present", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		graph := dag.NewMockDAG(ctrl)
		publisher := dag.NewMockPublisher(ctrl)
		signatureVerifier := dag.NewMockTransactionSignatureVerifier(ctrl)

		publisher.EXPECT().Subscribe(dag.AnyPayloadType, gomock.Any())
		graph.EXPECT().IsPresent(prev).Return(false, nil)
		tx, _, _ := dag.CreateTestTransaction(1, prev)
		graph.EXPECT().FindBetween(dag.MinTime(), dag.MaxTime()).Return([]dag.Transaction{tx}, nil)
		post := newPowerOnSelfTest(graph, publisher, signatureVerifier).(*defaultPowerOnSelfTest)
		err := post.verifyTransactions()
		assert.Contains(t, err.Error(), "transaction is referring to non-existing previous transaction")
	})
}

func Test_defaultPowerOnSelfTest_verifyTransactionSignature(t *testing.T) {
	t.Run("test fails", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		graph := dag.NewMockDAG(ctrl)
		publisher := dag.NewMockPublisher(ctrl)
		signatureVerifier := dag.NewMockTransactionSignatureVerifier(ctrl)

		publisher.EXPECT().Subscribe(dag.AnyPayloadType, gomock.Any())
		tx, _, _ := dag.CreateTestTransaction(1)
		signatureVerifier.EXPECT().Verify(tx).Return(errors.New("signature invalid"))
		post := newPowerOnSelfTest(graph, publisher, signatureVerifier).(*defaultPowerOnSelfTest)
		err := post.verifyTransactionSignature(tx, nil)
		assert.NoError(t, err)
	})
	t.Run("already finished", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		graph := dag.NewMockDAG(ctrl)
		publisher := dag.NewMockPublisher(ctrl)
		signatureVerifier := dag.NewMockTransactionSignatureVerifier(ctrl)

		publisher.EXPECT().Subscribe(dag.AnyPayloadType, gomock.Any())
		tx, _, _ := dag.CreateTestTransaction(1)
		post := newPowerOnSelfTest(graph, publisher, signatureVerifier).(*defaultPowerOnSelfTest)
		post.finished = true
		err := post.verifyTransactionSignature(tx, nil)
		assert.NoError(t, err)
	})
}
