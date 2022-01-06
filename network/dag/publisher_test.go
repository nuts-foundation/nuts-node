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

func TestReplayingDAGPublisher_Start(t *testing.T) {
	t.Run("err - failed to get Nats connection", func(t *testing.T) {
		ctrl := createPublisher(t)
		connectionPool := events.NewMockConnectionPool(ctrl.ctrl)
		ctrl.eventManager.EXPECT().Pool().Return(connectionPool)
		connectionPool.EXPECT().Acquire(gomock.Any()).Return(nil, nil, errors.New("b00m!"))

		err := ctrl.publisher.Start()

		if !assert.Error(t, err) {
			return
		}
		assert.EqualError(t, err, "failed to acquire a connection for events: b00m!")
	})
}

func TestReplayingPublisher(t *testing.T) {
	t.Run("empty graph at start", func(t *testing.T) {
		testDirectory := io.TestDirectory(t)
		ctx := context.Background()
		db := createBBoltDB(testDirectory)
		dag := NewBBoltDAG(db)
		payloadStore := NewBBoltPayloadStore(db)
		eventManager := events.NewStubEventManager()
		publisher := NewReplayingDAGPublisher(eventManager, payloadStore, dag).(*replayingDAGPublisher)
		received := false
		transaction := CreateTestTransactionWithJWK(1)
		publisher.Subscribe(transaction.PayloadType(), func(actualTransaction Transaction, actualPayload []byte) error {
			assert.Equal(t, transaction, actualTransaction)
			received = true
			return nil
		})
		publisher.Start()

		// Now add transaction and write payload to trigger the observers
		dag.Add(ctx, transaction)
		payloadStore.WritePayload(ctx, transaction.PayloadHash(), []byte{1, 2, 3})

		assert.True(t, received)
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

		eventManager := events.NewStubEventManager()
		publisher := NewReplayingDAGPublisher(eventManager, payloadStore, dag).(*replayingDAGPublisher)
		received := false
		publisher.Subscribe(transaction.PayloadType(), func(actualTransaction Transaction, actualPayload []byte) error {
			assert.Equal(t, transaction, actualTransaction)
			received = true
			return nil
		})
		publisher.Start()

		assert.True(t, received)
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

		received := false
		ctrl.publisher.Subscribe(transaction.PayloadType(), func(actualTransaction Transaction, actualPayload []byte) error {
			assert.Equal(t, transaction, actualTransaction)
			received = true
			return nil
		})
		ctrl.publisher.publishTransaction(ctx, transaction)
		assert.True(t, received)
	})
	t.Run("not received when transaction with pal header is skipped", func(t *testing.T) {
		ctrl := createPublisher(t)

		transaction := CreateSignedTestTransaction(1, time.Now(), [][]byte{{9, 8, 7}}, "foo/bar", true)

		received := false
		ctrl.privateTxCtx.EXPECT().PublishAsync(events.PrivateTransactionsSubject, gomock.Any()).Return(nil, nil)
		ctrl.publisher.Subscribe(transaction.PayloadType(), func(actualTransaction Transaction, actualPayload []byte) error {
			assert.Equal(t, transaction, actualTransaction)
			received = true
			return nil
		})
		ctrl.publisher.publishTransaction(ctx, transaction)
		assert.False(t, received)
	})
	t.Run("payload not present (but present later)", func(t *testing.T) {
		ctrl := createPublisher(t)

		transaction := CreateTestTransactionWithJWK(1)
		ctrl.payloadStore.EXPECT().ReadPayload(ctx, transaction.PayloadHash()).Return(nil, nil)

		received := false
		ctrl.publisher.Subscribe(transaction.PayloadType(), func(actualTransaction Transaction, actualPayload []byte) error {
			assert.Equal(t, transaction, actualTransaction)
			received = true
			return nil
		})
		ctrl.publisher.publishTransaction(ctx, transaction)
		assert.False(t, received)

		// Now add the payload and trigger observer func
		ctrl.payloadStore.EXPECT().ReadPayload(ctx, transaction.PayloadHash()).Return([]byte{1, 2, 3}, nil)
		ctrl.publisher.publishTransaction(ctx, transaction)

		assert.True(t, received)
	})
	t.Run("error reading payload", func(t *testing.T) {
		ctrl := createPublisher(t)

		transaction := CreateTestTransactionWithJWK(1)
		ctrl.payloadStore.EXPECT().ReadPayload(ctx, transaction.PayloadHash()).Return(nil, errors.New("failed"))

		received := false
		ctrl.publisher.Subscribe(transaction.PayloadType(), func(actualTransaction Transaction, actualPayload []byte) error {
			received = true
			return nil
		})
		ctrl.publisher.publishTransaction(ctx, transaction)
		assert.False(t, received)
	})
	t.Run("multiple subscribers", func(t *testing.T) {
		ctrl := createPublisher(t)

		transaction := CreateTestTransactionWithJWK(1)
		ctrl.payloadStore.EXPECT().ReadPayload(ctx, transaction.PayloadHash()).Return([]byte{1, 2, 3}, nil)

		calls := 0
		receiver := func(actualTransaction Transaction, actualPayload []byte) error {
			calls++
			return nil
		}
		ctrl.publisher.Subscribe(transaction.PayloadType(), receiver)
		ctrl.publisher.Subscribe(transaction.PayloadType(), receiver)

		ctrl.publisher.publishTransaction(ctx, transaction)

		assert.Equal(t, 2, calls)
	})
	t.Run("multiple subscribers, first fails", func(t *testing.T) {
		ctrl := createPublisher(t)

		transaction := CreateTestTransactionWithJWK(1)
		ctrl.payloadStore.EXPECT().ReadPayload(ctx, transaction.PayloadHash()).Return([]byte{1, 2, 3}, nil)
		calls := 0
		receiver := func(actualTransaction Transaction, actualPayload []byte) error {
			calls++
			return errors.New("failed")
		}
		ctrl.publisher.Subscribe(transaction.PayloadType(), receiver)
		ctrl.publisher.Subscribe(transaction.PayloadType(), receiver)
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
	publisher := NewReplayingDAGPublisher(eventManager, payloadStore, dag).(*replayingDAGPublisher)
	publisher.privateTxCtx = privateTxCtx
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
