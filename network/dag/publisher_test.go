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

		publisher := NewReplayingDAGPublisher(payloadStore, dag).(*replayingDAGPublisher)
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
	t.Run("no subscribers", func(t *testing.T) {
		publisher, ctrl, store := createPublisher(t)
		defer ctrl.Finish()
		ctx := context.Background()

		store.EXPECT().ReadPayload(ctx, gomock.Any()).Return([]byte{1, 2, 3}, nil)

		publisher.publishTransaction(ctx, CreateTestTransactionWithJWK(1))
	})
	t.Run("single subscriber", func(t *testing.T) {
		publisher, ctrl, store := createPublisher(t)
		defer ctrl.Finish()
		ctx := context.Background()

		transaction := CreateTestTransactionWithJWK(1)
		store.EXPECT().ReadPayload(ctx, transaction.PayloadHash()).Return([]byte{1, 2, 3}, nil)

		received := false
		publisher.Subscribe(transaction.PayloadType(), func(actualTransaction Transaction, actualPayload []byte) error {
			assert.Equal(t, transaction, actualTransaction)
			received = true
			return nil
		})
		publisher.publishTransaction(ctx, transaction)
		assert.True(t, received)
	})
	t.Run("payload not present (but present later)", func(t *testing.T) {
		publisher, ctrl, store := createPublisher(t)
		defer ctrl.Finish()
		ctx := context.Background()

		transaction := CreateTestTransactionWithJWK(1)
		store.EXPECT().ReadPayload(ctx, transaction.PayloadHash()).Return(nil, nil)

		received := false
		publisher.Subscribe(transaction.PayloadType(), func(actualTransaction Transaction, actualPayload []byte) error {
			assert.Equal(t, transaction, actualTransaction)
			received = true
			return nil
		})
		publisher.publishTransaction(ctx, transaction)
		assert.False(t, received)

		// Now add the payload and trigger observer func
		store.EXPECT().ReadPayload(ctx, transaction.PayloadHash()).Return([]byte{1, 2, 3}, nil)
		publisher.publishTransaction(ctx, transaction)

		assert.True(t, received)
	})
	t.Run("error reading payload", func(t *testing.T) {
		publisher, ctrl, store := createPublisher(t)
		defer ctrl.Finish()
		ctx := context.Background()

		transaction := CreateTestTransactionWithJWK(1)
		store.EXPECT().ReadPayload(ctx, transaction.PayloadHash()).Return(nil, errors.New("failed"))

		received := false
		publisher.Subscribe(transaction.PayloadType(), func(actualTransaction Transaction, actualPayload []byte) error {
			received = true
			return nil
		})
		publisher.publishTransaction(ctx, transaction)
		assert.False(t, received)
	})
	t.Run("multiple subscribers", func(t *testing.T) {
		publisher, ctrl, store := createPublisher(t)
		defer ctrl.Finish()
		ctx := context.Background()

		transaction := CreateTestTransactionWithJWK(1)
		store.EXPECT().ReadPayload(ctx, transaction.PayloadHash()).Return([]byte{1, 2, 3}, nil)

		calls := 0
		receiver := func(actualTransaction Transaction, actualPayload []byte) error {
			calls++
			return nil
		}
		publisher.Subscribe(transaction.PayloadType(), receiver)
		publisher.Subscribe(transaction.PayloadType(), receiver)

		publisher.publishTransaction(ctx, transaction)
		assert.Equal(t, 2, calls)
	})
	t.Run("multiple subscribers, first fails", func(t *testing.T) {
		publisher, ctrl, store := createPublisher(t)
		defer ctrl.Finish()
		ctx := context.Background()

		transaction := CreateTestTransactionWithJWK(1)
		store.EXPECT().ReadPayload(ctx, transaction.PayloadHash()).Return([]byte{1, 2, 3}, nil)
		calls := 0
		receiver := func(actualTransaction Transaction, actualPayload []byte) error {
			calls++
			return errors.New("failed")
		}
		publisher.Subscribe(transaction.PayloadType(), receiver)
		publisher.Subscribe(transaction.PayloadType(), receiver)
		publisher.publishTransaction(ctx, transaction)
		assert.Equal(t, 1, calls)
	})
}

func createPublisher(t *testing.T) (*replayingDAGPublisher, *gomock.Controller, *MockPayloadStore) {
	ctrl := gomock.NewController(t)
	payloadStore := NewMockPayloadStore(ctrl)
	payloadStore.EXPECT().RegisterObserver(gomock.Any())
	dag := NewMockDAG(ctrl)
	dag.EXPECT().RegisterObserver(gomock.Any())
	publisher := NewReplayingDAGPublisher(payloadStore, dag).(*replayingDAGPublisher)
	return publisher, ctrl, payloadStore
}
