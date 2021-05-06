package proto

import (
	"fmt"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/network/p2p"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/stretchr/testify/assert"
)

const peer = p2p.PeerID("test-peer")

var payload = []byte("Hello, World!")
var payloadHash = hash.SHA256Sum([]byte{1, 2, 3})

func TestProtocol_HandleAdvertedHashes(t *testing.T) {
	t.Run("no body (faulty use of protocol)", func(t *testing.T) {
		err := newContext(t).handle(&transport.NetworkMessage_AdvertHashes{})
		assert.NoError(t, err)
	})
	t.Run("body empty (faulty use of protocol)", func(t *testing.T) {
		msg := &transport.NetworkMessage_AdvertHashes{}
		msg.AdvertHashes = &transport.AdvertHashes{}
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
		ctx.graph().EXPECT().IsPresent(gomock.Any()).Return(false, nil)
		blocks := toBlocks(ctx.transactions)
		currentBlock := blocks[len(blocks)-1]
		currentBlock.heads[0] = hash.SHA256Sum([]byte{1, 2, 3}) // mutilate the head of the current block
		ctx.sender().EXPECT().sendTransactionListQuery(peer, currentBlock.start)
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
		ctx.sender().EXPECT().sendTransactionListQuery(peer, time.Time{})
		blocks := toBlocks(ctx.transactions)
		blocks[0].heads[0] = hash.SHA256Sum([]byte{1, 2, 3})
		msg := createAdvertHashesMessage(blocks)
		err := ctx.handle(msg)
		assert.NoError(t, err)
		ctx.assertNoNewOmnihashes()
	})
}

func TestProtocol_HandleTransactionListQuery(t *testing.T) {
	t.Run("no body (faulty use of protocol)", func(t *testing.T) {
		err := newContext(t).handle(&transport.NetworkMessage_TransactionListQuery{})
		assert.NoError(t, err)
	})
	t.Run("supplied block date is zero, requests historic block (allowed for now)", func(t *testing.T) {
		ctx := newContext(t)
		ctx.graph().EXPECT().FindBetween(time.Time{}, ctx.instance.blocks.get()[1].start)
		ctx.sender().EXPECT().sendTransactionList(peer, gomock.Any(), time.Time{})
		msg := &transport.NetworkMessage_TransactionListQuery{TransactionListQuery: &transport.TransactionListQuery{BlockDate: 0}}
		err := ctx.handle(msg)
		assert.NoError(t, err)
	})
	t.Run("respond with transaction list (happy flow)", func(t *testing.T) {
		ctx := newContext(t)
		ctx.graph().EXPECT().FindBetween(gomock.Any(), gomock.Any())
		ctx.sender().EXPECT().sendTransactionList(peer, gomock.Any(), gomock.Any())
		msg := &transport.NetworkMessage_TransactionListQuery{TransactionListQuery: &transport.TransactionListQuery{BlockDate: getBlockTimestamp(time.Now())}}
		err := ctx.handle(msg)
		assert.NoError(t, err)
	})
}

func TestProtocol_HandleTransactionList(t *testing.T) {
	t.Run("no body (faulty use of protocol)", func(t *testing.T) {
		err := newContext(t).handle(&transport.NetworkMessage_TransactionList{})
		assert.NoError(t, err)
	})
	t.Run("body empty (faulty use of protocol)", func(t *testing.T) {
		msg := &transport.NetworkMessage_TransactionList{}
		msg.TransactionList = &transport.TransactionList{}
		err := newContext(t).handle(msg)
		assert.NoError(t, err)
	})
	t.Run("empty list", func(t *testing.T) {
		ctx := newContext(t)
		msg := &transport.NetworkMessage_TransactionList{TransactionList: &transport.TransactionList{}}
		err := ctx.handle(msg)
		assert.NoError(t, err)
	})
	t.Run("non-empty list, all match (happy flow)", func(t *testing.T) {
		ctx := newContext(t)
		msg := &transport.NetworkMessage_TransactionList{
			TransactionList: &transport.TransactionList{
				BlockDate:    getBlockTimestamp(time.Now()),
				Transactions: toNetworkTransactions(toTransactions(ctx.transactions)),
			},
		}
		err := ctx.handle(msg)
		assert.NoError(t, err)
	})
}

func TestProtocol_HandleTransactionPayloadQuery(t *testing.T) {
	t.Run("no body (faulty use of protocol)", func(t *testing.T) {
		err := newContext(t).handle(&transport.NetworkMessage_TransactionPayloadQuery{})
		assert.NoError(t, err)
	})
	t.Run("body empty (faulty use of protocol)", func(t *testing.T) {
		msg := &transport.NetworkMessage_TransactionPayloadQuery{}
		msg.TransactionPayloadQuery = &transport.TransactionPayloadQuery{}
		err := newContext(t).handle(msg)
		assert.NoError(t, err)
	})
	t.Run("empty payload hash (faulty use of protocol)", func(t *testing.T) {
		ctx := newContext(t)
		msg := &transport.NetworkMessage_TransactionPayloadQuery{TransactionPayloadQuery: &transport.TransactionPayloadQuery{}}
		err := ctx.handle(msg)
		assert.NoError(t, err)
	})
	t.Run("payload present (happy flow)", func(t *testing.T) {
		ctx := newContext(t)
		payload := []byte("Hello, World!")
		ctx.payloadStore().EXPECT().ReadPayload(gomock.Any()).Return(payload, nil)
		payloadHash := hash.SHA256Sum([]byte{1, 2, 3})
		ctx.sender().EXPECT().sendTransactionPayload(peer, payloadHash, payload)
		msg := &transport.NetworkMessage_TransactionPayloadQuery{TransactionPayloadQuery: &transport.TransactionPayloadQuery{
			PayloadHash: payloadHash.Slice(),
		}}
		err := ctx.handle(msg)
		assert.NoError(t, err)
	})
	t.Run("payload not present (alt. flow)", func(t *testing.T) {
		ctx := newContext(t)
		ctx.payloadStore().EXPECT().ReadPayload(gomock.Any()).Return(nil, nil)
		payloadHash := hash.SHA256Sum([]byte{1, 2, 3})
		ctx.sender().EXPECT().sendTransactionPayload(peer, payloadHash, nil)
		msg := &transport.NetworkMessage_TransactionPayloadQuery{TransactionPayloadQuery: &transport.TransactionPayloadQuery{
			PayloadHash: payloadHash.Slice(),
		}}
		err := ctx.handle(msg)
		assert.NoError(t, err)
	})
}

func TestProtocol_HandleTransactionPayload(t *testing.T) {
	t.Run("no body (faulty use of protocol)", func(t *testing.T) {
		err := newContext(t).handle(&transport.NetworkMessage_TransactionPayload{})
		assert.NoError(t, err)
	})
	t.Run("body empty (faulty use of protocol)", func(t *testing.T) {
		msg := &transport.NetworkMessage_TransactionPayload{}
		msg.TransactionPayload = &transport.TransactionPayload{}
		err := newContext(t).handle(msg)
		assert.NoError(t, err)
	})
	t.Run("empty payload hash (faulty use of protocol)", func(t *testing.T) {
		ctx := newContext(t)
		msg := &transport.NetworkMessage_TransactionPayload{TransactionPayload: &transport.TransactionPayload{}}
		err := ctx.handle(msg)
		assert.NoError(t, err)
	})
	t.Run("peer sent payload, not present locally yet (happy flow)", func(t *testing.T) {
		ctx := newContext(t)
		ctx.graph().EXPECT().GetByPayloadHash(payloadHash).Return([]dag.Transaction{&testTX{}}, nil)
		ctx.payloadStore().EXPECT().IsPresent(payloadHash).Return(false, nil)
		ctx.payloadStore().EXPECT().WritePayload(payloadHash, payload).Return(nil)
		msg := &transport.NetworkMessage_TransactionPayload{TransactionPayload: &transport.TransactionPayload{
			Data:        payload,
			PayloadHash: payloadHash.Slice(),
		}}
		err := ctx.handle(msg)
		assert.NoError(t, err)
	})
	t.Run("peer sent payload, already present locally yet (alt. flow)", func(t *testing.T) {
		ctx := newContext(t)
		ctx.graph().EXPECT().GetByPayloadHash(payloadHash).Return([]dag.Transaction{&testTX{}}, nil)
		ctx.payloadStore().EXPECT().IsPresent(payloadHash).Return(true, nil)
		msg := &transport.NetworkMessage_TransactionPayload{TransactionPayload: &transport.TransactionPayload{
			Data:        payload,
			PayloadHash: payloadHash.Slice(),
		}}
		err := ctx.handle(msg)
		assert.NoError(t, err)
	})
	t.Run("peer sent payload, unknown transaction (attacker flow)", func(t *testing.T) {
		ctx := newContext(t)
		ctx.graph().EXPECT().GetByPayloadHash(payloadHash).Return([]dag.Transaction{}, nil)
		msg := &transport.NetworkMessage_TransactionPayload{TransactionPayload: &transport.TransactionPayload{
			Data:        payload,
			PayloadHash: payloadHash.Slice(),
		}}
		err := ctx.handle(msg)
		assert.NoError(t, err)
	})
	t.Run("peer didn't send payload (alt. flow)", func(t *testing.T) {
		ctx := newContext(t)
		msg := &transport.NetworkMessage_TransactionPayload{TransactionPayload: &transport.TransactionPayload{
			PayloadHash: payloadHash.Slice(),
		}}
		err := ctx.handle(msg)
		assert.NoError(t, err)
	})
}

func Test_checkTransactionOnLocalNode(t *testing.T) {
	tx, _, _ := dag.CreateTestTransaction(1)
	t.Run("payload present (happy flow)", func(t *testing.T) {
		ctx := newContext(t)
		ctx.graph().EXPECT().IsPresent(tx.Ref()).Return(true, nil)
		ctx.payloadStore().EXPECT().IsPresent(tx.PayloadHash()).Return(true, nil)
		err := ctx.instance.checkTransactionOnLocalNode(peer, tx.Ref(), tx.Data())
		assert.NoError(t, err)
	})
	t.Run("payload not present (alt. flow)", func(t *testing.T) {
		ctx := newContext(t)
		ctx.graph().EXPECT().IsPresent(tx.Ref()).Return(true, nil)
		ctx.payloadStore().EXPECT().IsPresent(tx.PayloadHash()).Return(false, nil)
		ctx.sender().EXPECT().sendTransactionPayloadQuery(peer, tx.PayloadHash())
		err := ctx.instance.checkTransactionOnLocalNode(peer, tx.Ref(), tx.Data())
		assert.NoError(t, err)
	})
	t.Run("tx not present  (alt. flow)", func(t *testing.T) {
		ctx := newContext(t)
		ctx.graph().EXPECT().IsPresent(tx.Ref()).Return(false, nil)
		ctx.graph().EXPECT().Add(tx)
		ctx.sender().EXPECT().sendTransactionPayloadQuery(peer, tx.PayloadHash())
		err := ctx.instance.checkTransactionOnLocalNode(peer, tx.Ref(), tx.Data())
		assert.NoError(t, err)
	})
	t.Run("invalid transaction", func(t *testing.T) {
		ctx := newContext(t)
		data := []byte{1, 2, 3}
		err := ctx.instance.checkTransactionOnLocalNode(peer, hash.SHA256Sum(data), data)
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

func toTransactions(txs []testTX) []dag.Transaction {
	var result []dag.Transaction
	for _, curr := range txs {
		result = append(result, &curr)
	}
	return result
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
	instance := NewProtocol().(*protocol)
	instance.payloadStore = dag.NewMockPayloadStore(mockCtrl)
	instance.sender = NewMockmessageSender(mockCtrl)
	instance.graph = dag.NewMockDAG(mockCtrl)
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
		data: []byte("TX B"),
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

func (ctx testContext) payloadStore() *dag.MockPayloadStore {
	return ctx.instance.payloadStore.(*dag.MockPayloadStore)
}

func (ctx testContext) graph() *dag.MockDAG {
	return ctx.instance.graph.(*dag.MockDAG)
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
	case *transport.NetworkMessage_AdvertHashes:
		envelope.Message = msg
	case *transport.NetworkMessage_TransactionListQuery:
		envelope.Message = msg
	case *transport.NetworkMessage_TransactionList:
		envelope.Message = msg
	case *transport.NetworkMessage_TransactionPayloadQuery:
		envelope.Message = msg
	case *transport.NetworkMessage_TransactionPayload:
		envelope.Message = msg
	default:
		panic(fmt.Sprintf("Can't handle msg type: %T", msg))
	}
	return ctx.instance.handleMessage(p2p.PeerMessage{
		Peer:    peer,
		Message: &envelope,
	})
}
