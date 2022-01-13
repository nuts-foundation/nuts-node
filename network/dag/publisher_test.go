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
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-node/events"

	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/stretchr/testify/assert"
)

func TestReplayingPublisher(t *testing.T) {
	t.Run("empty graph at start", func(t *testing.T) {
		testDirectory := io.TestDirectory(t)
		ctx := context.Background()
		db := createBBoltDB(testDirectory)
		dag := NewBBoltDAG(db)
		payloadStore := NewBBoltPayloadStore(db)
		publisher := NewReplayingDAGPublisher(payloadStore, dag).(*replayingDAGPublisher)
		calls := 0
		transaction := CreateTestTransactionWithJWK(1)
		publisher.Subscribe(TransactionAddedEvent, transaction.PayloadType(), func(actualTransaction Transaction, actualPayload []byte) error {
			assert.Equal(t, transaction, actualTransaction)
			calls++
			return nil
		})
		publisher.Start()

		// Now add transaction and write payload to trigger the observers
		dag.Add(ctx, transaction)
		payloadStore.WritePayload(ctx, transaction.PayloadHash(), []byte{1, 2, 3})

		assert.Equal(t, 1, calls)
	})
	t.Run("non-empty graph at start", func(t *testing.T) {
		testDirectory := io.TestDirectory(t)
		ctx := context.Background()
		db := createBBoltDB(testDirectory)
		dag := NewBBoltDAG(db)
		payloadStore := NewBBoltPayloadStore(db)
		transaction := CreateTestTransactionWithJWK(1)
		err := dag.Add(ctx, transaction)
		if !assert.NoError(t, err) {
			return
		}
		err = payloadStore.WritePayload(ctx, transaction.PayloadHash(), []byte{1, 2, 3})
		if !assert.NoError(t, err) {
			return
		}

		publisher := NewReplayingDAGPublisher(payloadStore, dag).(*replayingDAGPublisher)
		calls := 0
		publisher.Subscribe(TransactionAddedEvent, transaction.PayloadType(), func(actualTransaction Transaction, actualPayload []byte) error {
			assert.Equal(t, transaction, actualTransaction)
			calls++
			return nil
		})
		publisher.Start()

		assert.Equal(t, calls, 1)
	})
}

func TestReplayingPublisher_publishTransaction(t *testing.T) {
	ctx := context.Background()
	t.Run("no subscribers", func(t *testing.T) {
		ctrl := createPublisher(t)
		ctrl.payloadStore.EXPECT().ReadPayload(ctx, gomock.Any()).Return([]byte{1, 2, 3}, nil)

		ctrl.publisher.publishTransaction(ctx, CreateTestTransactionWithJWK(1))
	})
	t.Run("single subscriber", func(t *testing.T) {
		ctrl := createPublisher(t)

		transaction := CreateTestTransactionWithJWK(1)
		ctrl.payloadStore.EXPECT().ReadPayload(ctx, transaction.PayloadHash()).Return([]byte{1, 2, 3}, nil)

		calls := 0
		ctrl.publisher.Subscribe(TransactionAddedEvent, transaction.PayloadType(), func(actualTransaction Transaction, actualPayload []byte) error {
			assert.Equal(t, transaction, actualTransaction)
			calls++
			return nil
		})
		ctrl.publisher.publishTransaction(ctx, transaction)
		assert.Equal(t, calls, 1)
	})
	t.Run("subscribers on multiple event types", func(t *testing.T) {
		ctrl := createPublisher(t)

		transaction := CreateTestTransactionWithJWK(1)
		ctrl.payloadStore.EXPECT().ReadPayload(ctx, transaction.PayloadHash()).Return([]byte{1, 2, 3}, nil)

		txAddedCalls := 0
		txPayloadAddedCalls := 0
		ctrl.publisher.Subscribe(TransactionAddedEvent, transaction.PayloadType(), func(actualTransaction Transaction, actualPayload []byte) error {
			assert.Equal(t, transaction, actualTransaction)
			txAddedCalls++
			return nil
		})
		ctrl.publisher.Subscribe(TransactionPayloadAddedEvent, transaction.PayloadType(), func(actualTransaction Transaction, actualPayload []byte) error {
			assert.Equal(t, transaction, actualTransaction)
			txPayloadAddedCalls++
			return nil
		})
		ctrl.publisher.publishTransaction(ctx, transaction)

		assert.Equal(t, 1, txAddedCalls)
		assert.Equal(t, 1, txPayloadAddedCalls)
	})

	t.Run("not received when transaction with pal header is skipped", func(t *testing.T) {
		ctrl := createPublisher(t)

		transaction := CreateSignedTestTransaction(1, time.Now(), [][]byte{{9, 8, 7}}, "foo/bar", true)

		ctrl.payloadStore.EXPECT().ReadPayload(ctx, transaction.PayloadHash()).Return(nil, nil)
		ctrl.privateTxCtx.EXPECT().PublishAsync(events.PrivateTransactionsSubject, gomock.Any()).Return(nil, nil)

		txAddedCalled := 0
		ctrl.publisher.Subscribe(TransactionAddedEvent, transaction.PayloadType(), func(actualTransaction Transaction, actualPayload []byte) error {
			txAddedCalled++
			return nil
		})
		txPayloadAddedCalled := 0
		ctrl.publisher.Subscribe(TransactionPayloadAddedEvent, transaction.PayloadType(), func(actualTransaction Transaction, actualPayload []byte) error {
			txPayloadAddedCalled++
			return nil
		})

		ctrl.publisher.publishTransaction(ctx, transaction)
		assert.Equal(t, 0, txAddedCalled)
		assert.Equal(t, 0, txPayloadAddedCalled)
	})
	t.Run("payload not present (but present later)", func(t *testing.T) {
		ctrl := createPublisher(t)

		transaction := CreateTestTransactionWithJWK(1)
		ctrl.payloadStore.EXPECT().ReadPayload(ctx, transaction.PayloadHash()).Return(nil, nil)

		txAddedCalled := 0
		ctrl.publisher.Subscribe(TransactionAddedEvent, transaction.PayloadType(), func(actualTransaction Transaction, actualPayload []byte) error {
			assert.Equal(t, transaction, actualTransaction)
			txAddedCalled++
			return nil
		})
		txPayloadAddedCalled := 0
		ctrl.publisher.Subscribe(TransactionPayloadAddedEvent, transaction.PayloadType(), func(actualTransaction Transaction, actualPayload []byte) error {
			assert.Equal(t, transaction, actualTransaction)
			txPayloadAddedCalled++
			return nil
		})

		ctrl.publisher.publishTransaction(ctx, transaction)
		assert.Equal(t, 0, txAddedCalled)
		assert.Equal(t, 0, txPayloadAddedCalled)

		// Now add the payload and trigger subscribers
		ctrl.payloadStore.EXPECT().ReadPayload(ctx, transaction.PayloadHash()).Return([]byte{1, 2, 3}, nil)
		ctrl.publisher.publishTransaction(ctx, transaction)

		assert.Equal(t, 1, txAddedCalled)
		assert.Equal(t, 1, txPayloadAddedCalled)
	})

	t.Run("error reading payload", func(t *testing.T) {
		ctrl := createPublisher(t)

		transaction := CreateTestTransactionWithJWK(1)
		ctrl.payloadStore.EXPECT().ReadPayload(ctx, transaction.PayloadHash()).Return(nil, errors.New("failed"))

		txAddedCalled := false
		ctrl.publisher.Subscribe(TransactionAddedEvent, transaction.PayloadType(), func(actualTransaction Transaction, actualPayload []byte) error {
			txAddedCalled = true
			return nil
		})
		txPayloadAddedCalled := false
		ctrl.publisher.Subscribe(TransactionAddedEvent, transaction.PayloadType(), func(actualTransaction Transaction, actualPayload []byte) error {
			txPayloadAddedCalled = true
			return nil
		})
		ctrl.publisher.publishTransaction(ctx, transaction)
		assert.False(t, txAddedCalled)
		assert.False(t, txPayloadAddedCalled)
	})
	t.Run("multiple subscribers on single event type", func(t *testing.T) {
		ctrl := createPublisher(t)

		transaction := CreateTestTransactionWithJWK(1)
		ctrl.payloadStore.EXPECT().ReadPayload(ctx, transaction.PayloadHash()).Return([]byte{1, 2, 3}, nil)

		calls := 0
		receiver := func(actualTransaction Transaction, actualPayload []byte) error {
			calls++
			return nil
		}
		ctrl.publisher.Subscribe(TransactionAddedEvent, transaction.PayloadType(), receiver)
		ctrl.publisher.Subscribe(TransactionAddedEvent, transaction.PayloadType(), receiver)

		ctrl.publisher.publishTransaction(ctx, transaction)

		assert.Equal(t, 2, calls)
	})
	t.Run("multiple subscribers on single event type, first fails", func(t *testing.T) {
		ctrl := createPublisher(t)

		transaction := CreateTestTransactionWithJWK(1)
		ctrl.payloadStore.EXPECT().ReadPayload(ctx, transaction.PayloadHash()).Return([]byte{1, 2, 3}, nil)
		calls := 0
		receiver := func(actualTransaction Transaction, actualPayload []byte) error {
			calls++
			return errors.New("failed")
		}
		ctrl.publisher.Subscribe(TransactionAddedEvent, transaction.PayloadType(), receiver)
		ctrl.publisher.Subscribe(TransactionAddedEvent, transaction.PayloadType(), receiver)
		ctrl.publisher.publishTransaction(ctx, transaction)
		assert.Equal(t, 1, calls)
	})
}

func createPublisher(t *testing.T) testPublisher {
	ctrl := gomock.NewController(t)
	payloadStore := NewMockPayloadStore(ctrl)
	dag := NewMockDAG(ctrl)
	privateTxCtx := events.NewMockJetStreamContext(ctrl)
	eventManager := events.NewMockEvent(ctrl)
	publisher := NewReplayingDAGPublisher(payloadStore, dag).(*replayingDAGPublisher)
	return testPublisher{
		ctrl:         ctrl,
		payloadStore: payloadStore,
		eventManager: eventManager,
		privateTxCtx: privateTxCtx,
		publisher:    publisher,
	}
}

type testPublisher struct {
	ctrl         *gomock.Controller
	payloadStore *MockPayloadStore
	eventManager *events.MockEvent
	privateTxCtx *events.MockJetStreamContext
	publisher    *replayingDAGPublisher
}
