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

	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/stretchr/testify/assert"
)

func TestReplayingPublisher(t *testing.T) {
	tx0 := CreateTestTransactionWithJWK(1)

	t.Run("empty graph at start", func(t *testing.T) {
		ctx := context.Background()
		publisher, dag, payloadStore := newPublisher(t)
		calls := 0

		publisher.Subscribe(TransactionAddedEvent, tx0.PayloadType(), func(actualTransaction Transaction, actualPayload []byte) error {
			assert.Equal(t, tx0, actualTransaction)
			calls++
			return nil
		})
		publisher.Start()

		// Now add transaction and write payload to trigger the observers
		dag.Add(ctx, tx0)
		payloadStore.WritePayload(ctx, tx0.PayloadHash(), []byte{1, 2, 3})
		publisher.transactionAdded(ctx, tx0, nil)

		assert.Equal(t, 1, calls)
	})
	t.Run("non-empty graph at start", func(t *testing.T) {
		ctx := context.Background()
		publisher, dag, payloadStore := newPublisher(t)
		err := dag.Add(ctx, tx0)
		if !assert.NoError(t, err) {
			return
		}
		err = payloadStore.WritePayload(ctx, tx0.PayloadHash(), []byte{1, 2, 3})
		if !assert.NoError(t, err) {
			return
		}

		calls := 0
		publisher.Subscribe(TransactionAddedEvent, tx0.PayloadType(), func(actualTransaction Transaction, actualPayload []byte) error {
			assert.Equal(t, tx0, actualTransaction)
			calls++
			return nil
		})
		publisher.Start()

		assert.Equal(t, calls, 1)
	})
}

func TestReplayingDAGPublisher_replay(t *testing.T) {
	tx0 := CreateTestTransactionWithJWK(1)

	t.Run("tx without payload", func(t *testing.T) {
		ctx := context.Background()
		publisher, dag, _ := newPublisher(t)
		dag.Add(ctx, tx0)
		calls := 0

		publisher.Subscribe(TransactionAddedEvent, tx0.PayloadType(), func(actualTransaction Transaction, actualPayload []byte) error {
			calls++
			return nil
		})
		publisher.Start()

		assert.Equal(t, 1, calls)
	})

	t.Run("txs without payload - first is blocking", func(t *testing.T) {
		tx1 := CreateTestTransactionWithJWK(2, tx0)
		ctx := context.Background()
		publisher, dag, _ := newPublisher(t)
		dag.Add(ctx, tx0)
		dag.Add(ctx, tx1)
		txAddedCalls := 0
		txPayloadAddedCalls := 0

		publisher.Subscribe(TransactionAddedEvent, tx0.PayloadType(), func(actualTransaction Transaction, actualPayload []byte) error {
			txAddedCalls++
			return nil
		})
		publisher.Subscribe(TransactionPayloadAddedEvent, tx0.PayloadType(), func(actualTransaction Transaction, actualPayload []byte) error {
			txPayloadAddedCalls++
			return nil
		})
		publisher.Start()

		assert.Equal(t, 1, txAddedCalls)
		assert.Equal(t, 0, txPayloadAddedCalls)
	})

	t.Run("txs with payload - first is blocking", func(t *testing.T) {
		tx1 := CreateTestTransactionWithJWK(2, tx0)
		ctx := context.Background()
		publisher, dag, payloadStore := newPublisher(t)
		dag.Add(ctx, tx0)
		dag.Add(ctx, tx1)
		payloadStore.WritePayload(ctx, tx0.PayloadHash(), []byte{1})
		payloadStore.WritePayload(ctx, tx1.PayloadHash(), []byte{2})
		txAddedCalls := 0
		txPayloadAddedCalls := 0

		publisher.Subscribe(TransactionAddedEvent, tx0.PayloadType(), func(actualTransaction Transaction, actualPayload []byte) error {
			txAddedCalls++
			return nil
		})
		publisher.Subscribe(TransactionPayloadAddedEvent, tx0.PayloadType(), func(actualTransaction Transaction, actualPayload []byte) error {
			txPayloadAddedCalls++
			return nil
		})
		publisher.Start()

		assert.Equal(t, 2, txAddedCalls)
		assert.Equal(t, 2, txPayloadAddedCalls)
	})
	t.Run("txs not processed again when payload has been processed", func(t *testing.T) {
		tx1 := CreateTestTransactionWithJWK(2, tx0)
		tx2 := CreateTestTransactionWithJWK(3, tx1)
		ctx := context.Background()
		publisher, dag, payloadStore := newPublisher(t)
		dag.Add(ctx, tx0, tx1)
		payloadStore.WritePayload(ctx, tx0.PayloadHash(), []byte{1})
		payloadStore.WritePayload(ctx, tx1.PayloadHash(), []byte{2})
		txAddedCalls := 0
		txPayloadAddedCalls := 0

		publisher.Subscribe(TransactionAddedEvent, tx0.PayloadType(), func(actualTransaction Transaction, actualPayload []byte) error {
			txAddedCalls++
			return nil
		})
		publisher.Subscribe(TransactionPayloadAddedEvent, tx0.PayloadType(), func(actualTransaction Transaction, actualPayload []byte) error {
			txPayloadAddedCalls++
			return nil
		})
		publisher.Start()
		dag.Add(ctx, tx2)
		// trigger another processing with an old hash
		publisher.payloadWritten(ctx, nil, []byte{1})

		assert.Equal(t, 2, txAddedCalls)
		assert.Equal(t, 2, txPayloadAddedCalls)
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
		payloadStore := NewBBoltPayloadStore(db)
		graph := newBBoltDAG(db)
		publisher := NewReplayingDAGPublisher(payloadStore, graph).(*replayingDAGPublisher)
		ctx := context.Background()

		txA := CreateTestTransactionWithJWK(1)
		txAPayload := []byte{0, 0, 0, 1}
		one := CreateTestTransactionWithJWK(2, txA)
		two := CreateTestTransactionWithJWK(3, txA)
		var txB, txC Transaction
		var txBPayload, txCPayload []byte
		if one.Ref().Compare(two.Ref()) <= 0 {
			txB = one
			txC = two
			txBPayload = []byte{0, 0, 0, 2}
			txCPayload = []byte{0, 0, 0, 3}
		} else {
			txB = two
			txC = one
			txBPayload = []byte{0, 0, 0, 3}
			txCPayload = []byte{0, 0, 0, 2}
		}
		txD := CreateTestTransactionWithJWK(4, txB, txC)
		txDPayload := []byte{0, 0, 0, 4}

		txB.(*transaction).payloadType = "foo/bar"
		txD.(*transaction).payloadType = "foo/bar"

		var transactions int
		var payloads int
		publisher.Subscribe(TransactionAddedEvent, AnyPayloadType, func(actualTransaction Transaction, actualPayload []byte) error {
			transactions++
			return nil
		})
		publisher.Subscribe(TransactionPayloadAddedEvent, AnyPayloadType, func(actualTransaction Transaction, actualPayload []byte) error {
			payloads++
			return nil
		})
		graph.Add(ctx, txA, txB, txC, txD)

		// Write payload for A and C, check events
		_ = payloadStore.WritePayload(ctx, txA.PayloadHash(), txAPayload)
		_ = payloadStore.WritePayload(ctx, txC.PayloadHash(), txCPayload)
		publisher.transactionAdded(ctx, txA, nil)
		publisher.transactionAdded(ctx, txB, nil)
		publisher.transactionAdded(ctx, txC, nil)
		publisher.transactionAdded(ctx, txD, nil)
		publisher.payloadWritten(ctx, nil, txAPayload)
		publisher.payloadWritten(ctx, nil, txCPayload)

		assert.Equal(t, 1, payloads)
		assert.Equal(t, 4, transactions)

		// Write payload for D, nothing should be published
		_ = payloadStore.WritePayload(ctx, txD.PayloadHash(), txDPayload)
		publisher.payloadWritten(ctx, nil, txDPayload)
		assert.Equal(t, 1, payloads)
		// Another call for B
		assert.Equal(t, 4, transactions)

		// Write payload for B, B, C and D should be published
		_ = payloadStore.WritePayload(ctx, txB.PayloadHash(), txBPayload)
		publisher.payloadWritten(ctx, nil, txBPayload)
		assert.Equal(t, 4, payloads)
		// + B, C, D
		assert.Equal(t, 4, transactions)
	})
}

func TestReplayingPublisher_Publish(t *testing.T) {
	ctx := context.Background()
	rootTX := CreateTestTransactionWithJWK(1)
	rootTXPayload := []byte{0, 0, 0, 1}
	t.Run("no subscribers", func(t *testing.T) {
		ctrl := createPublisher(t)
		ctrl.payloadStore.WritePayload(ctx, rootTX.PayloadHash(), rootTXPayload)

		ctrl.graph.Add(ctx, rootTX)

		ctrl.publisher.transactionAdded(ctx, rootTX, nil)
	})
	t.Run("single subscriber", func(t *testing.T) {
		ctrl := createPublisher(t)

		ctrl.graph.Add(ctx, rootTX)

		calls := 0
		ctrl.publisher.Subscribe(TransactionPayloadAddedEvent, rootTX.PayloadType(), func(actualTransaction Transaction, actualPayload []byte) error {
			assert.Equal(t, rootTX, actualTransaction)
			calls++
			return nil
		})

		// Add TX, payload not yet present
		ctrl.publisher.transactionAdded(ctx, rootTX, nil)

		// Add payload as well, now payload IS present
		ctrl.payloadStore.WritePayload(ctx, rootTX.PayloadHash(), rootTXPayload)
		ctrl.publisher.payloadWritten(ctx, nil, rootTXPayload)

		assert.Equal(t, 1, calls)
	})
	t.Run("local node call order (payloadWritten first, then transactionAdded)", func(t *testing.T) {
		ctrl := createPublisher(t)

		ctrl.payloadStore.WritePayload(ctx, rootTX.PayloadHash(), rootTXPayload)

		txAddedCalls := 0
		ctrl.publisher.Subscribe(TransactionAddedEvent, rootTX.PayloadType(), func(actualTransaction Transaction, actualPayload []byte) error {
			txAddedCalls++
			return nil
		})
		payloadAddedCalls := 0
		ctrl.publisher.Subscribe(TransactionPayloadAddedEvent, rootTX.PayloadType(), func(actualTransaction Transaction, actualPayload []byte) error {
			payloadAddedCalls++
			return nil
		})

		// First write payload
		ctrl.publisher.payloadWritten(ctx, nil, rootTXPayload)
		assert.Equal(t, 0, payloadAddedCalls)
		assert.Equal(t, 0, txAddedCalls)

		// Then add TX
		_ = ctrl.graph.Add(ctx, rootTX)
		ctrl.publisher.transactionAdded(ctx, rootTX, nil)
		assert.Equal(t, 1, payloadAddedCalls)
		assert.Equal(t, 1, txAddedCalls)
	})
	t.Run("error reading TX from DAG", func(t *testing.T) {
		ctrl := createPublisher(t)

		_ = ctrl.db.Close()

		txAddedCalls := 0
		ctrl.publisher.Subscribe(TransactionAddedEvent, rootTX.PayloadType(), func(actualTransaction Transaction, actualPayload []byte) error {
			txAddedCalls++
			return nil
		})
		payloadAddedCalls := 0
		ctrl.publisher.Subscribe(TransactionPayloadAddedEvent, rootTX.PayloadType(), func(actualTransaction Transaction, actualPayload []byte) error {
			payloadAddedCalls++
			return nil
		})

		ctrl.publisher.payloadWritten(ctx, nil, rootTXPayload)
		assert.Equal(t, 0, payloadAddedCalls)
		assert.Equal(t, 0, txAddedCalls)
	})
	t.Run("subscribers on multiple event types", func(t *testing.T) {
		ctrl := createPublisher(t)

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

		// Add TX, payload not yet present
		ctrl.publisher.transactionAdded(ctx, rootTX, nil)

		// Add payload as well, now payload IS present
		ctrl.payloadStore.WritePayload(ctx, rootTX.PayloadHash(), rootTXPayload)
		ctrl.publisher.payloadWritten(ctx, nil, rootTXPayload)

		assert.Equal(t, 1, txAddedCalls)
		assert.Equal(t, 1, txPayloadAddedCalls)
	})
	t.Run("not received when transaction with pal header is skipped", func(t *testing.T) {
		ctrl := createPublisher(t)

		tx := CreateSignedTestTransaction(1, time.Now(), [][]byte{{9, 8, 7}}, "foo/bar", true)

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

		ctrl.publisher.transactionAdded(ctx, tx, nil)

		assert.Equal(t, 1, txAddedCalled)
		assert.Equal(t, 0, txPayloadAddedCalled)
	})
	t.Run("payload not present (but present later)", func(t *testing.T) {
		ctrl := createPublisher(t)

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

		ctrl.publisher.transactionAdded(ctx, rootTX, nil)

		assert.Equal(t, 1, txAddedCalled)
		assert.Equal(t, 0, txPayloadAddedCalled)

		// Now add the payload and trigger subscribers
		ctrl.payloadStore.WritePayload(ctx, rootTX.PayloadHash(), rootTXPayload)

		ctrl.publisher.payloadWritten(ctx, nil, rootTXPayload)

		assert.Equal(t, 1, txAddedCalled)
		assert.Equal(t, 1, txPayloadAddedCalled)
	})

	t.Run("multiple subscribers on single event type", func(t *testing.T) {
		ctrl := createPublisher(t)

		ctrl.payloadStore.WritePayload(ctx, rootTX.PayloadHash(), rootTXPayload)
		ctrl.graph.Add(ctx, rootTX)

		calls := 0
		receiver := func(actualTransaction Transaction, actualPayload []byte) error {
			calls++
			return nil
		}
		ctrl.publisher.Subscribe(TransactionAddedEvent, rootTX.PayloadType(), receiver)
		ctrl.publisher.Subscribe(TransactionAddedEvent, rootTX.PayloadType(), receiver)

		ctrl.publisher.transactionAdded(ctx, rootTX, nil)

		assert.Equal(t, 2, calls)
	})
	t.Run("multiple subscribers on single event type, first fails", func(t *testing.T) {
		ctrl := createPublisher(t)

		ctrl.payloadStore.WritePayload(ctx, rootTX.PayloadHash(), rootTXPayload)
		ctrl.graph.Add(ctx, rootTX)

		calls := 0
		receiver := func(actualTransaction Transaction, actualPayload []byte) error {
			calls++
			return errors.New("failed")
		}
		ctrl.publisher.Subscribe(TransactionAddedEvent, rootTX.PayloadType(), receiver)
		ctrl.publisher.Subscribe(TransactionAddedEvent, rootTX.PayloadType(), receiver)

		ctrl.publisher.transactionAdded(ctx, rootTX, nil)

		assert.Equal(t, 1, calls)
	})
}

func createPublisher(t *testing.T) testPublisher {
	db, _ := bbolt.Open(path.Join(io.TestDirectory(t), "dag.bbolt"), os.ModePerm, nil)
	t.Cleanup(func() {
		_ = db.Close()
	})
	payloadStore := NewBBoltPayloadStore(db)
	graph := newBBoltDAG(db)
	publisher := NewReplayingDAGPublisher(payloadStore, graph).(*replayingDAGPublisher)
	return testPublisher{
		payloadStore: payloadStore,
		publisher:    publisher,
		graph:        graph,
		db:           db,
	}
}

type testPublisher struct {
	payloadStore PayloadStore
	publisher    *replayingDAGPublisher
	graph        *bboltDAG
	db           *bbolt.DB
}

func newPublisher(t *testing.T) (*replayingDAGPublisher, *bboltDAG, PayloadStore) {
	testDirectory := io.TestDirectory(t)
	db := createBBoltDB(testDirectory)
	dag := newBBoltDAG(db)
	payloadStore := NewBBoltPayloadStore(db)
	return NewReplayingDAGPublisher(payloadStore, dag).(*replayingDAGPublisher), dag, payloadStore
}
