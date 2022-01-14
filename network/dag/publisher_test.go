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
	"os"
	"path"
	"testing"
	"time"

	"go.etcd.io/bbolt"

	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-node/events"
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

func TestReplayingPublisher_Publish(t *testing.T) {
	ctx := context.Background()
	rootTX := CreateTestTransactionWithJWK(1)
	rootTXPayload := []byte{1, 2, 3}
	t.Run("no subscribers", func(t *testing.T) {
		ctrl := createPublisher(t)
		ctrl.payloadStore.EXPECT().ReadPayload(gomock.Any(), rootTX.PayloadHash()).Return(rootTXPayload, nil)

		ctrl.graph.Add(ctx, rootTX)

		ctrl.publisher.transactionAdded(ctx, rootTX)
	})
	t.Run("parallel branched, which are blocked", func(t *testing.T) {
		// Given graph "A <- [B, C] <- D"
		// When payload for A is written
		//  And payload for C is written
		// Then TransactionPayloadAddedEvent for A and C should be emitted
		// When payload for B is written
		// Then TransactionPayloadAddedEvent for B and D should be emitted
		db, _ := bbolt.Open(path.Join(io.TestDirectory(t), "dag.bbolt"), os.ModePerm, nil)
		t.Cleanup(func() {
			_ = db.Close()
		})
		payloadStore :=  NewBBoltPayloadStore(db)
		graph := NewBBoltDAG(db)
		publisher := NewReplayingDAGPublisher(payloadStore, graph).(*replayingDAGPublisher)

		txA := rootTX
		txB := CreateTestTransactionWithJWK(2, txA.Ref())
		txC := CreateTestTransactionWithJWK(3, txA.Ref())
		txD := CreateTestTransactionWithJWK(4, txB.Ref(), txC.Ref())

		var capture []Transaction
		publisher.Subscribe(TransactionPayloadAddedEvent, txA.PayloadType(), func(actualTransaction Transaction, actualPayload []byte) error {
			println("capture")
			capture = append(capture, actualTransaction)
			return nil
		})
		graph.RegisterObserver(publisher.transactionAdded)
		payloadStore.RegisterObserver(publisher.payloadWritten)
		graph.Add(ctx, txA, txB, txC, txD)

		println("A = ", txA.Ref().String())
		println("B = ", txB.Ref().String())
		println("C = ", txC.Ref().String())
		println("D = ", txD.Ref().String())

		// Write payload for A and C, check events
		err := payloadStore.WritePayload(ctx, txA.PayloadHash(), rootTXPayload)
		if !assert.NoError(t, err) {
			return
		}
		err = payloadStore.WritePayload(ctx, txC.PayloadHash(), rootTXPayload)
		if !assert.NoError(t, err) {
			return
		}
		println(len(capture))
		for _, tx := range capture {
			println(tx.Ref().String())
		}
		if !assert.Len(t, capture, 2) {
			return
		}
		assert.Equal(t, txA.Ref(), capture[0].Ref())
		assert.Equal(t, txC.Ref(), capture[1].Ref())
		capture = nil

		// Write payload for D, nothing should be published
		payloadStore.WritePayload(ctx, txD.PayloadHash(), rootTXPayload)
		println(capture[0].Ref().String())
		assert.Empty(t, capture)

		// Write payload for B, B and D should be published
		payloadStore.WritePayload(ctx, txB.PayloadHash(), rootTXPayload)
		assert.Len(t, capture, 2)
		assert.Equal(t, txB.Ref(), capture[0])
		assert.Equal(t, txD.Ref(), capture[1])
	})
	t.Run("single subscriber", func(t *testing.T) {
		ctrl := createPublisher(t)

		ctrl.payloadStore.EXPECT().ReadPayload(gomock.Any(), rootTX.PayloadHash()).Return(rootTXPayload, nil)
		ctrl.graph.Add(ctx, rootTX)

		calls := 0
		ctrl.publisher.Subscribe(TransactionPayloadAddedEvent, rootTX.PayloadType(), func(actualTransaction Transaction, actualPayload []byte) error {
			assert.Equal(t, rootTX, actualTransaction)
			calls++
			return nil
		})

		ctrl.publisher.transactionAdded(ctx, rootTX)
		ctrl.publisher.payloadWritten(ctx, nil)

		assert.Equal(t, 1, calls)
	})
	t.Run("subscribers on multiple event types", func(t *testing.T) {
		ctrl := createPublisher(t)

		ctrl.payloadStore.EXPECT().ReadPayload(gomock.Any(), rootTX.PayloadHash()).Return(rootTXPayload, nil)
		ctrl.graph.Add(ctx, rootTX)

		txAddedCalls := 0
		txPayloadAddedCalls := 0
		ctrl.publisher.Subscribe(TransactionAddedEvent, rootTX.PayloadType(), func(actualTransaction Transaction, actualPayload []byte) error {
			assert.Equal(t, rootTX, actualTransaction)
			txAddedCalls++
			return nil
		})
		ctrl.publisher.Subscribe(TransactionPayloadAddedEvent, rootTX.PayloadType(), func(actualTransaction Transaction, actualPayload []byte) error {
			assert.Equal(t, rootTX, actualTransaction)
			txPayloadAddedCalls++
			return nil
		})

		ctrl.publisher.transactionAdded(ctx, rootTX)
		ctrl.publisher.payloadWritten(ctx, nil)

		assert.Equal(t, 1, txAddedCalls)
		assert.Equal(t, 1, txPayloadAddedCalls)
	})
	t.Run("not received when transaction with pal header is skipped", func(t *testing.T) {
		ctrl := createPublisher(t)

		tx := CreateSignedTestTransaction(1, time.Now(), [][]byte{{9, 8, 7}}, "foo/bar", true)

		ctrl.payloadStore.EXPECT().ReadPayload(gomock.Any(), tx.PayloadHash()).AnyTimes().Return(nil, nil)
		ctrl.graph.Add(ctx, tx)

		txAddedCalled := 0
		ctrl.publisher.Subscribe(TransactionAddedEvent, tx.PayloadType(), func(actualTransaction Transaction, actualPayload []byte) error {
			txAddedCalled++
			return nil
		})
		txPayloadAddedCalled := 0
		ctrl.publisher.Subscribe(TransactionPayloadAddedEvent, tx.PayloadType(), func(actualTransaction Transaction, actualPayload []byte) error {
			txPayloadAddedCalled++
			return nil
		})

		ctrl.publisher.transactionAdded(ctx, tx)

		assert.Equal(t, 1, txAddedCalled)
		assert.Equal(t, 0, txPayloadAddedCalled)
	})
	t.Run("payload not present (but present later)", func(t *testing.T) {
		ctrl := createPublisher(t)

		ctrl.payloadStore.EXPECT().ReadPayload(gomock.Any(), rootTX.PayloadHash()).Return(nil, nil)
		ctrl.graph.Add(ctx, rootTX)

		txAddedCalled := 0
		ctrl.publisher.Subscribe(TransactionAddedEvent, rootTX.PayloadType(), func(actualTransaction Transaction, actualPayload []byte) error {
			assert.Equal(t, rootTX, actualTransaction)
			txAddedCalled++
			return nil
		})
		txPayloadAddedCalled := 0
		ctrl.publisher.Subscribe(TransactionPayloadAddedEvent, rootTX.PayloadType(), func(actualTransaction Transaction, actualPayload []byte) error {
			assert.Equal(t, rootTX, actualTransaction)
			txPayloadAddedCalled++
			return nil
		})

		ctrl.publisher.transactionAdded(ctx, rootTX)

		assert.Equal(t, 1, txAddedCalled)
		assert.Equal(t, 0, txPayloadAddedCalled)

		// Now add the payload and trigger subscribers
		ctrl.payloadStore.EXPECT().ReadPayload(gomock.Any(), rootTX.PayloadHash()).Return(rootTXPayload, nil)

		ctrl.publisher.payloadWritten(ctx, nil)

		assert.Equal(t, 1, txAddedCalled)
		assert.Equal(t, 1, txPayloadAddedCalled)
	})

	t.Run("error reading payload", func(t *testing.T) {
		ctrl := createPublisher(t)

		ctrl.payloadStore.EXPECT().ReadPayload(gomock.Any(), rootTX.PayloadHash()).MinTimes(1).Return(nil, errors.New("failed"))
		ctrl.graph.Add(ctx, rootTX)

		txAddedCalled := false
		ctrl.publisher.Subscribe(TransactionAddedEvent, rootTX.PayloadType(), func(actualTransaction Transaction, actualPayload []byte) error {
			txAddedCalled = true
			return nil
		})
		txPayloadAddedCalled := false
		ctrl.publisher.Subscribe(TransactionPayloadAddedEvent, rootTX.PayloadType(), func(actualTransaction Transaction, actualPayload []byte) error {
			txPayloadAddedCalled = true
			return nil
		})

		ctrl.publisher.transactionAdded(ctx, rootTX)
		ctrl.publisher.payloadWritten(ctx, nil)

		assert.True(t, txAddedCalled)
		assert.False(t, txPayloadAddedCalled)
	})
	t.Run("multiple subscribers on single event type", func(t *testing.T) {
		ctrl := createPublisher(t)

		ctrl.payloadStore.EXPECT().ReadPayload(gomock.Any(), rootTX.PayloadHash()).Return(rootTXPayload, nil)
		ctrl.graph.Add(ctx, rootTX)

		calls := 0
		receiver := func(actualTransaction Transaction, actualPayload []byte) error {
			calls++
			return nil
		}
		ctrl.publisher.Subscribe(TransactionAddedEvent, rootTX.PayloadType(), receiver)
		ctrl.publisher.Subscribe(TransactionAddedEvent, rootTX.PayloadType(), receiver)

		ctrl.publisher.transactionAdded(ctx, rootTX)

		assert.Equal(t, 2, calls)
	})
	t.Run("multiple subscribers on single event type, first fails", func(t *testing.T) {
		ctrl := createPublisher(t)

		ctrl.payloadStore.EXPECT().ReadPayload(gomock.Any(), rootTX.PayloadHash()).Return(rootTXPayload, nil)
		ctrl.graph.Add(ctx, rootTX)

		calls := 0
		receiver := func(actualTransaction Transaction, actualPayload []byte) error {
			calls++
			return errors.New("failed")
		}
		ctrl.publisher.Subscribe(TransactionAddedEvent, rootTX.PayloadType(), receiver)
		ctrl.publisher.Subscribe(TransactionAddedEvent, rootTX.PayloadType(), receiver)

		ctrl.publisher.transactionAdded(ctx, rootTX)

		assert.Equal(t, 1, calls)
	})
}

func createPublisher(t *testing.T) testPublisher {
	ctrl := gomock.NewController(t)
	payloadStore := NewMockPayloadStore(ctrl)
	db, _ := bbolt.Open(path.Join(io.TestDirectory(t), "dag.bbolt"), os.ModePerm, nil)
	t.Cleanup(func() {
		_ = db.Close()
	})
	graph := NewBBoltDAG(db)
	privateTxCtx := events.NewMockJetStreamContext(ctrl)
	eventManager := events.NewMockEvent(ctrl)
	publisher := NewReplayingDAGPublisher(payloadStore, graph).(*replayingDAGPublisher)
	return testPublisher{
		ctrl:         ctrl,
		payloadStore: payloadStore,
		eventManager: eventManager,
		privateTxCtx: privateTxCtx,
		publisher:    publisher,
		graph:        graph,
	}
}

type testPublisher struct {
	ctrl         *gomock.Controller
	payloadStore *MockPayloadStore
	eventManager *events.MockEvent
	privateTxCtx *events.MockJetStreamContext
	publisher    *replayingDAGPublisher
	graph        DAG
}
