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

package logic

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
	graph.EXPECT().GetByPayloadHash(ctx, tx1.PayloadHash()).Return([]dag.Transaction{}, nil)

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
