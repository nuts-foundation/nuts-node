package proto

import (
	"context"
	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_missingPayloadCollector(t *testing.T) {
	ctrl := gomock.NewController(t)
	ctx := context.Background()

	// 2 transactions: TX0 is OK, TX1 is missing payload
	tx0, _, _ := dag.CreateTestTransaction(0)
	tx1, _, _ := dag.CreateTestTransaction(1, tx0.Ref())

	graph := dag.NewMockDAG(ctrl)
	// looks a bit odd because of mocking callbacks
	graph.EXPECT().PayloadHashes(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, consumer func(payloadHash hash.SHA256Hash) error) error {
		assert.NoError(t, consumer(tx0.PayloadHash()))
		return consumer(tx1.PayloadHash())
	})

	payloadStore := dag.NewMockPayloadStore(ctrl)
	// looks a bit odd because of mocking callbacks
	payloadStore.EXPECT().ReadMany(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, consumer func(ctx context.Context, reader dag.PayloadReader) error) error {
		return consumer(ctx, payloadStore)
	})
	payloadStore.EXPECT().IsPresent(ctx, tx0.PayloadHash()).Return(true, nil)
	payloadStore.EXPECT().IsPresent(ctx, tx1.PayloadHash()).Return(false, nil)

	sender := NewMockmessageSender(ctrl)
	sender.EXPECT().broadcastTransactionPayloadQuery(tx1.PayloadHash())

	collector := broadcastingMissingPayloadCollector{
		graph:        graph,
		payloadStore: payloadStore,
		sender:       sender,
	}

	err := collector.findAndQueryMissingPayloads()
	assert.NoError(t, err)
}
