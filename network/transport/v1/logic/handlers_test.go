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
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/nuts-foundation/nuts-node/network/transport/v1/protobuf"

	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/stretchr/testify/assert"
)

const peerID = transport.PeerID("test-peer")

var peer = transport.Peer{
	ID: peerID,
}

var payload = []byte("Hello, World!")
var payloadHash = hash.SHA256Sum([]byte{1, 2, 3})

func TestProtocol_HandleAdvertedHashes(t *testing.T) {
	t.Run("no body (faulty use of protocol)", func(t *testing.T) {
		err := newContext(t).handle(&protobuf.NetworkMessage_AdvertHashes{})
		assert.NoError(t, err)
	})
	t.Run("body empty (faulty use of protocol)", func(t *testing.T) {
		msg := &protobuf.NetworkMessage_AdvertHashes{}
		msg.AdvertHashes = &protobuf.AdvertHashes{}
		err := newContext(t).handle(msg)
		assert.NoError(t, err)
	})
	t.Run("blocks are equal (happy flow)", func(t *testing.T) {
		ctx := newContext(t)
		msg := createAdvertHashesMessage(toBlocks(ctx.transactions))
		err := ctx.handle(msg)
		assert.NoError(t, err)
		ctx.assertNewOmnihash()
	})
	t.Run("block differs, query transaction list (alt. flow)", func(t *testing.T) {
		ctx := newContext(t)
		ctx.state().EXPECT().IsPresent(gomock.Any(), gomock.Any()).Return(false, nil)
		blocks := toBlocks(ctx.transactions)
		currentBlock := blocks[len(blocks)-1]
		currentBlock.heads[0] = hash.SHA256Sum([]byte{1, 2, 3}) // mutilate the head of the current block
		ctx.sender().EXPECT().sendTransactionListQuery(peerID, currentBlock.start)
		msg := createAdvertHashesMessage(blocks)
		err := ctx.handle(msg)
		assert.NoError(t, err)
		ctx.assertNewOmnihash()
	})
	t.Run("block differs -> peer is missing tx (alt. flow)", func(t *testing.T) {
		ctx := newContext(t)
		blocks := toBlocks(ctx.transactions)
		currentBlock := blocks[len(blocks)-1]
		currentBlock.heads = []hash.SHA256Hash{} // mutilate the head of the current block
		msg := createAdvertHashesMessage(blocks)
		err := ctx.handle(msg)
		assert.NoError(t, err)
		ctx.assertNewOmnihash()
	})
	t.Run("current block date differs (temporary protocol error)", func(t *testing.T) {
		msg := createAdvertHashesMessage([]dagBlock{{
			start: time.Now(),
			heads: nil,
		}})
		ctx := newContext(t)
		err := ctx.handle(msg)
		assert.NoError(t, err)
		ctx.assertNoNewOmnihashes()
	})
	t.Run("number of blocks differ (protocol error)", func(t *testing.T) {
		msg := createAdvertHashesMessage([]dagBlock{{
			start: startOfDay(time.Now()),
			heads: nil,
		}})
		ctx := newContext(t)
		err := ctx.handle(msg)
		assert.NoError(t, err)
		ctx.assertNoNewOmnihashes()
	})
	t.Run("historic block differs (queries historic block for now)", func(t *testing.T) {
		ctx := newContext(t)
		ctx.sender().EXPECT().sendTransactionListQuery(peerID, time.Time{})
		blocks := toBlocks(ctx.transactions)
		blocks[0].heads[0] = hash.SHA256Sum([]byte{1, 2, 3})
		msg := createAdvertHashesMessage(blocks)
		err := ctx.handle(msg)
		assert.NoError(t, err)
		ctx.assertNewOmnihash()
	})
}

func TestProtocol_HandleTransactionListQuery(t *testing.T) {
	t.Run("no body (faulty use of protocol)", func(t *testing.T) {
		err := newContext(t).handle(&protobuf.NetworkMessage_TransactionListQuery{})
		assert.NoError(t, err)
	})
	t.Run("supplied block date is zero, requests historic block (allowed for now)", func(t *testing.T) {
		ctx := newContext(t)
		ctx.state().EXPECT().FindBetween(gomock.Any(), time.Time{}, ctx.instance.blocks.get()[1].start)
		ctx.sender().EXPECT().sendTransactionList(peerID, gomock.Any(), time.Time{})
		msg := &protobuf.NetworkMessage_TransactionListQuery{TransactionListQuery: &protobuf.TransactionListQuery{BlockDate: 0}}
		err := ctx.handle(msg)
		assert.NoError(t, err)
	})
	t.Run("respond with transaction list (happy flow)", func(t *testing.T) {
		ctx := newContext(t)
		ctx.state().EXPECT().FindBetween(gomock.Any(), gomock.Any(), gomock.Any())
		ctx.sender().EXPECT().sendTransactionList(peerID, gomock.Any(), gomock.Any())
		msg := &protobuf.NetworkMessage_TransactionListQuery{TransactionListQuery: &protobuf.TransactionListQuery{BlockDate: getBlockTimestamp(time.Now())}}
		err := ctx.handle(msg)
		assert.NoError(t, err)
	})
}

func TestProtocol_HandleTransactionList(t *testing.T) {
	t.Run("no body (faulty use of protocol)", func(t *testing.T) {
		err := newContext(t).handle(&protobuf.NetworkMessage_TransactionList{})
		assert.NoError(t, err)
	})
	t.Run("body empty (faulty use of protocol)", func(t *testing.T) {
		msg := &protobuf.NetworkMessage_TransactionList{}
		msg.TransactionList = &protobuf.TransactionList{}
		err := newContext(t).handle(msg)
		assert.NoError(t, err)
	})
	t.Run("empty list", func(t *testing.T) {
		ctx := newContext(t)
		msg := &protobuf.NetworkMessage_TransactionList{TransactionList: &protobuf.TransactionList{}}
		err := ctx.handle(msg)
		assert.NoError(t, err)
	})
	t.Run("non-empty list (happy flow)", func(t *testing.T) {
		ctx := newContext(t)
		tx, _, _ := dag.CreateTestTransaction(1)
		ctx.state().EXPECT().IsPresent(gomock.Any(), tx.Ref()).Return(true, nil)
		ctx.state().EXPECT().IsPayloadPresent(gomock.Any(), tx.PayloadHash()).Return(true, nil)
		msg := &protobuf.NetworkMessage_TransactionList{
			TransactionList: &protobuf.TransactionList{
				BlockDate:    getBlockTimestamp(time.Now()),
				Transactions: toNetworkTransactions([]dag.Transaction{tx}),
			},
		}
		err := ctx.handle(msg)
		assert.NoError(t, err)
	})
	t.Run("remove from slice", func(t *testing.T) {
		slice := []string{"a"}
		idx := 0
		slice = append(slice[:idx], slice[idx+1:]...)
		fmt.Printf("%v\n", slice)
	})
	t.Run("non-empty list, processing error", func(t *testing.T) {
		ctx := newContext(t)
		tx1, _, _ := dag.CreateTestTransaction(1)
		ctx.state().EXPECT().IsPresent(gomock.Any(), tx1.Ref()).Return(false, nil)
		ctx.state().EXPECT().Add(gomock.Any(), tx1, nil).Return(errors.New("failed"))
		msg := &protobuf.NetworkMessage_TransactionList{
			TransactionList: &protobuf.TransactionList{
				BlockDate:    getBlockTimestamp(time.Now()),
				Transactions: toNetworkTransactions([]dag.Transaction{tx1}),
			},
		}
		err := ctx.handle(msg)
		assert.Contains(t, err.Error(), "unable to add received transaction to DAG")
	})
	t.Run("non-empty list, missing prevs", func(t *testing.T) {
		testCtx := newContext(t)
		// TX(1) should be processed properly
		// TX(2) is unprocessable because its previous TXs are missing
		// TX(3) should be processed properly
		ctx := context.Background()
		tx1, _, _ := dag.CreateTestTransaction(1)
		testCtx.state().EXPECT().IsPresent(ctx, tx1.Ref()).MinTimes(1).Return(true, nil)
		testCtx.state().EXPECT().IsPayloadPresent(ctx, tx1.PayloadHash()).Return(true, nil)
		tx2, _, _ := dag.CreateTestTransaction(1)
		testCtx.state().EXPECT().IsPresent(ctx, tx2.Ref()).MinTimes(1).Return(false, nil)
		testCtx.state().EXPECT().Add(gomock.Any(), tx2, gomock.Any()).MinTimes(1).Return(fmt.Errorf("error: %w", dag.ErrPreviousTransactionMissing))
		tx3, _, _ := dag.CreateTestTransaction(1)
		testCtx.state().EXPECT().IsPresent(ctx, tx3.Ref()).MinTimes(1).Return(true, nil)
		testCtx.state().EXPECT().IsPayloadPresent(ctx, tx3.PayloadHash()).Return(true, nil)
		msg := &protobuf.NetworkMessage_TransactionList{
			TransactionList: &protobuf.TransactionList{
				BlockDate:    getBlockTimestamp(time.Now()),
				Transactions: toNetworkTransactions([]dag.Transaction{tx1, tx2, tx3}),
			},
		}
		err := testCtx.handle(msg)
		assert.NoError(t, err)
	})
}

func TestProtocol_HandleTransactionPayloadQuery(t *testing.T) {
	t.Run("no body (faulty use of protocol)", func(t *testing.T) {
		err := newContext(t).handle(&protobuf.NetworkMessage_TransactionPayloadQuery{})
		assert.NoError(t, err)
	})
	t.Run("body empty (faulty use of protocol)", func(t *testing.T) {
		msg := &protobuf.NetworkMessage_TransactionPayloadQuery{}
		msg.TransactionPayloadQuery = &protobuf.TransactionPayloadQuery{}
		err := newContext(t).handle(msg)
		assert.NoError(t, err)
	})
	t.Run("empty payload hash (faulty use of protocol)", func(t *testing.T) {
		ctx := newContext(t)
		msg := &protobuf.NetworkMessage_TransactionPayloadQuery{TransactionPayloadQuery: &protobuf.TransactionPayloadQuery{}}
		err := ctx.handle(msg)
		assert.NoError(t, err)
	})
	t.Run("payload present (happy flow)", func(t *testing.T) {
		ctx := newContext(t)
		payload := []byte("Hello, World!")
		payloadHash := hash.SHA256Sum([]byte{1, 2, 3})

		ctx.state().EXPECT().GetByPayloadHash(gomock.Any(), payloadHash).Return([]dag.Transaction{}, nil)
		ctx.state().EXPECT().ReadPayload(gomock.Any(), gomock.Any()).Return(payload, nil)
		ctx.sender().EXPECT().sendTransactionPayload(peerID, payloadHash, payload)
		msg := &protobuf.NetworkMessage_TransactionPayloadQuery{TransactionPayloadQuery: &protobuf.TransactionPayloadQuery{
			PayloadHash: payloadHash.Slice(),
		}}
		err := ctx.handle(msg)
		assert.NoError(t, err)
	})
	t.Run("payload present but with PAL header", func(t *testing.T) {
		ctx := newContext(t)
		payloadHash := hash.SHA256Sum([]byte{1, 2, 3})

		ctx.state().EXPECT().GetByPayloadHash(gomock.Any(), payloadHash).Return([]dag.Transaction{
			&testTX{
				pal: [][]byte{{1}},
			},
		}, nil)
		ctx.sender().EXPECT().sendTransactionPayload(peerID, payloadHash, []byte{})
		msg := &protobuf.NetworkMessage_TransactionPayloadQuery{TransactionPayloadQuery: &protobuf.TransactionPayloadQuery{
			PayloadHash: payloadHash.Slice(),
		}}
		err := ctx.handle(msg)
		assert.NoError(t, err)
	})
	t.Run("payload not present (alt. flow)", func(t *testing.T) {
		ctx := newContext(t)
		payloadHash := hash.SHA256Sum([]byte{1, 2, 3})

		ctx.state().EXPECT().GetByPayloadHash(gomock.Any(), payloadHash).Return([]dag.Transaction{}, nil)
		ctx.state().EXPECT().ReadPayload(gomock.Any(), gomock.Any()).Return(nil, nil)
		ctx.sender().EXPECT().sendTransactionPayload(peerID, payloadHash, nil)
		msg := &protobuf.NetworkMessage_TransactionPayloadQuery{TransactionPayloadQuery: &protobuf.TransactionPayloadQuery{
			PayloadHash: payloadHash.Slice(),
		}}
		err := ctx.handle(msg)
		assert.NoError(t, err)
	})
}

func TestProtocol_HandleTransactionPayload(t *testing.T) {
	t.Run("no body (faulty use of protocol)", func(t *testing.T) {
		err := newContext(t).handle(&protobuf.NetworkMessage_TransactionPayload{})
		assert.NoError(t, err)
	})
	t.Run("body empty (faulty use of protocol)", func(t *testing.T) {
		msg := &protobuf.NetworkMessage_TransactionPayload{}
		msg.TransactionPayload = &protobuf.TransactionPayload{}
		err := newContext(t).handle(msg)
		assert.NoError(t, err)
	})
	t.Run("empty payload hash (faulty use of protocol)", func(t *testing.T) {
		ctx := newContext(t)
		msg := &protobuf.NetworkMessage_TransactionPayload{TransactionPayload: &protobuf.TransactionPayload{}}
		err := ctx.handle(msg)
		assert.NoError(t, err)
	})
	t.Run("peer sent payload, not present locally yet (happy flow)", func(t *testing.T) {
		ctx := newContext(t)
		ctx.state().EXPECT().GetByPayloadHash(gomock.Any(), payloadHash).Return([]dag.Transaction{&testTX{}}, nil)
		ctx.state().EXPECT().WritePayload(gomock.Any(), payloadHash, nil, payload).Return(nil)
		msg := &protobuf.NetworkMessage_TransactionPayload{TransactionPayload: &protobuf.TransactionPayload{
			Data:        payload,
			PayloadHash: payloadHash.Slice(),
		}}
		err := ctx.handle(msg)
		assert.NoError(t, err)
	})
	t.Run("peer sent payload, unknown transaction (attacker flow)", func(t *testing.T) {
		ctx := newContext(t)
		ctx.state().EXPECT().GetByPayloadHash(gomock.Any(), payloadHash).Return([]dag.Transaction{}, nil)
		msg := &protobuf.NetworkMessage_TransactionPayload{TransactionPayload: &protobuf.TransactionPayload{
			Data:        payload,
			PayloadHash: payloadHash.Slice(),
		}}
		err := ctx.handle(msg)
		assert.NoError(t, err)
	})
	t.Run("peer didn't send payload (alt. flow)", func(t *testing.T) {
		ctx := newContext(t)
		msg := &protobuf.NetworkMessage_TransactionPayload{TransactionPayload: &protobuf.TransactionPayload{
			PayloadHash: payloadHash.Slice(),
		}}
		err := ctx.handle(msg)
		assert.NoError(t, err)
	})
}

func TestProtocol_handleDiagnostics(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctx := newContext(t)
		msg := &protobuf.NetworkMessage_DiagnosticsBroadcast{DiagnosticsBroadcast: &protobuf.Diagnostics{
			Uptime:               1000,
			Peers:                []string{"test"},
			NumberOfTransactions: 5,
			SoftwareVersion:      "1.0",
			SoftwareID:           "TEST",
		}}
		err := ctx.handle(msg)

		assert.NoError(t, err)
		actual := ctx.instance.peerDiagnostics[peerID]
		assert.Equal(t, 1000*time.Second, actual.Uptime)
		assert.Equal(t, []transport.PeerID{"test"}, actual.Peers)
		assert.Equal(t, uint32(5), actual.NumberOfTransactions)
		assert.Equal(t, "1.0", actual.SoftwareVersion)
		assert.Equal(t, "TEST", actual.SoftwareID)
	})
}

func TestProtocol_handleMessage(t *testing.T) {
	t.Run("empty message", func(t *testing.T) {
		ctx := newContext(t)
		envelope := createEnvelope()
		err := ctx.instance.Handle(peer, &envelope)
		assert.EqualError(t, err, "envelope doesn't contain any (handleable) messages")
	})
}

func Test_checkTransactionOnLocalNode(t *testing.T) {
	tx, _, _ := dag.CreateTestTransaction(1)
	t.Run("payload present (happy flow)", func(t *testing.T) {
		ctx := newContext(t)
		ctx.state().EXPECT().IsPresent(gomock.Any(), tx.Ref()).Return(true, nil)
		ctx.state().EXPECT().IsPayloadPresent(gomock.Any(), tx.PayloadHash()).Return(true, nil)
		err := ctx.instance.checkTransactionOnLocalNode(context.Background(), peerID, tx.Ref(), tx.Data())
		assert.NoError(t, err)
	})
	t.Run("payload not present (alt. flow)", func(t *testing.T) {
		ctx := newContext(t)
		ctx.state().EXPECT().IsPresent(gomock.Any(), tx.Ref()).Return(true, nil)
		ctx.state().EXPECT().IsPayloadPresent(gomock.Any(), tx.PayloadHash()).Return(false, nil)
		ctx.sender().EXPECT().sendTransactionPayloadQuery(peerID, tx.PayloadHash())
		err := ctx.instance.checkTransactionOnLocalNode(context.Background(), peerID, tx.Ref(), tx.Data())
		assert.NoError(t, err)
	})
	t.Run("tx not present  (alt. flow)", func(t *testing.T) {
		ctx := newContext(t)
		ctx.state().EXPECT().IsPresent(gomock.Any(), tx.Ref()).Return(false, nil)
		ctx.state().EXPECT().Add(gomock.Any(), tx, gomock.Any())
		ctx.sender().EXPECT().sendTransactionPayloadQuery(peerID, tx.PayloadHash())
		err := ctx.instance.checkTransactionOnLocalNode(context.Background(), peerID, tx.Ref(), tx.Data())
		assert.NoError(t, err)
	})
	t.Run("invalid transaction", func(t *testing.T) {
		ctx := newContext(t)
		data := []byte{1, 2, 3}
		err := ctx.instance.checkTransactionOnLocalNode(context.Background(), peerID, hash.SHA256Sum(data), data)
		assert.Contains(t, err.Error(), "unable to parse transaction")
	})
}

func toBlocks(txs []testTX) []dagBlock {
	blx := newDAGBlocks()
	for _, tx := range txs {
		if err := blx.addTransaction(&tx, nil); err != nil {
			panic(err)
		}
	}
	return blx.get()
}

type testContext struct {
	instance     *protocol
	mockCtrl     *gomock.Controller
	transactions []testTX
	t            *testing.T
}

func newContext(t *testing.T) *testContext {
	mockCtrl := gomock.NewController(t)
	t.Cleanup(func() {
		mockCtrl.Finish()
	})
	instance := NewProtocol(nil, nil, nil, nil).(*protocol)
	instance.sender = NewMockmessageSender(mockCtrl)
	instance.state = dag.NewMockState(mockCtrl)
	txA := testTX{
		data: []byte("TX A"),
		sigt: time.Now().AddDate(0, 0, numberOfBlocks*-1),
	}
	txB := testTX{
		data: []byte("TX B"),
		sigt: time.Now().AddDate(0, 0, -1),
		prev: []hash.SHA256Hash{txA.Ref()},
	}
	txC := testTX{
		data: []byte("TX C"),
		sigt: time.Now(),
		prev: []hash.SHA256Hash{txB.Ref()},
	}
	result := &testContext{
		instance:     instance,
		mockCtrl:     mockCtrl,
		t:            t,
		transactions: []testTX{txA, txB, txC},
	}
	return result
}

func (ctx testContext) sender() *MockmessageSender {
	return ctx.instance.sender.(*MockmessageSender)
}

func (ctx testContext) state() *dag.MockState {
	return ctx.instance.state.(*dag.MockState)
}

func (ctx testContext) assertNoNewOmnihashes() {
	assert.Empty(ctx.t, ctx.instance.peerOmnihashChannel, "expected no new peer omnihashes")
}

func (ctx testContext) assertNewOmnihash() {
	assert.Len(ctx.t, ctx.instance.peerOmnihashChannel, 1, "expected 1 hash in the omnihash channel")
}

func (ctx testContext) handle(msg interface{}) error {
	for _, tx := range ctx.transactions {
		if err := ctx.instance.blocks.addTransaction(&tx, nil); err != nil {
			panic(err)
		}
	}
	envelope := createEnvelope()
	switch msg := msg.(type) {
	case *protobuf.NetworkMessage_AdvertHashes:
		envelope.Message = msg
	case *protobuf.NetworkMessage_TransactionListQuery:
		envelope.Message = msg
	case *protobuf.NetworkMessage_TransactionList:
		envelope.Message = msg
	case *protobuf.NetworkMessage_TransactionPayloadQuery:
		envelope.Message = msg
	case *protobuf.NetworkMessage_TransactionPayload:
		envelope.Message = msg
	case *protobuf.NetworkMessage_DiagnosticsBroadcast:
		envelope.Message = msg
	default:
		panic(fmt.Sprintf("Can't handle msg type: %T", msg))
	}
	return ctx.instance.Handle(peer, &envelope)
}
