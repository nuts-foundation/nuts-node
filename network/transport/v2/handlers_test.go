package v2

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/nuts-foundation/nuts-node/network/transport/grpc"
	"github.com/stretchr/testify/assert"
)

var peer = transport.Peer{
	ID:      "abc",
	Address: "abc:5555",
}

var peerDID, _ = did.ParseDID("did:nuts:peer")
var authenticatedPeer = transport.Peer{
	ID:      "abc",
	Address: "abc:5555",
	NodeDID: *peerDID,
}

func Test_protocol_handle(t *testing.T) {
	t.Run("no handleable messages", func(t *testing.T) {
		p := New(nil, nil).(*protocol)
		err := p.Handle(peer, &Envelope{})
		assert.EqualError(t, err, "envelope doesn't contain any (handleable) messages")
	})
}

func Test_protocol_handleHello(t *testing.T) {
	err := New(nil, nil).Handle(peer, &Envelope{Message: &Envelope_Hello{}})
	assert.NoError(t, err)
}

func Test_protocol_handleTransactionPayload(t *testing.T) {
	payload := []byte("Hello, World!")
	tx, _, _ := dag.CreateTestTransactionEx(0, hash.SHA256Sum(payload), nil)

	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		graph := dag.NewMockDAG(ctrl)
		graph.EXPECT().Get(gomock.Any(), tx.Ref()).Return(tx, nil)
		payloadStore := dag.NewMockPayloadStore(ctrl)
		payloadStore.EXPECT().WritePayload(gomock.Any(), tx.PayloadHash(), payload)
		p := New(graph, payloadStore).(*protocol)

		err := p.Handle(peer, &Envelope{Message: &Envelope_TransactionPayload{&TransactionPayload{TransactionRef: tx.Ref().Slice(), Data: payload}}})

		assert.NoError(t, err)
	})
	t.Run("error - no tx ref", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		graph := dag.NewMockDAG(ctrl)
		payloadStore := dag.NewMockPayloadStore(ctrl)
		p := New(graph, payloadStore).(*protocol)

		envelope := &Envelope{Message: &Envelope_TransactionPayload{&TransactionPayload{}}}
		err := p.Handle(peer, envelope)

		assert.EqualError(t, err, "message is missing transaction reference")
	})
	t.Run("error - no data", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		graph := dag.NewMockDAG(ctrl)
		payloadStore := dag.NewMockPayloadStore(ctrl)
		p := New(graph, payloadStore).(*protocol)

		err := p.Handle(peer, &Envelope{Message: &Envelope_TransactionPayload{&TransactionPayload{TransactionRef: []byte{1, 2, 3}}}})

		assert.EqualError(t, err, "peer does not have transaction payload (tx=0102030000000000000000000000000000000000000000000000000000000000)")
	})
	t.Run("error - payload does not match hash", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		graph := dag.NewMockDAG(ctrl)
		graph.EXPECT().Get(gomock.Any(), tx.Ref()).Return(tx, nil)
		payloadStore := dag.NewMockPayloadStore(ctrl)
		p := New(graph, payloadStore).(*protocol)

		err := p.Handle(peer, &Envelope{Message: &Envelope_TransactionPayload{&TransactionPayload{TransactionRef: tx.Ref().Slice(), Data: []byte("Hello, victim!")}}})

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "peer sent payload that doesn't match payload hash")
	})
	t.Run("error - tx not present", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		graph := dag.NewMockDAG(ctrl)
		graph.EXPECT().Get(gomock.Any(), tx.Ref()).Return(nil, nil)
		payloadStore := dag.NewMockPayloadStore(ctrl)
		p := New(graph, payloadStore).(*protocol)

		err := p.Handle(peer, &Envelope{Message: &Envelope_TransactionPayload{&TransactionPayload{TransactionRef: tx.Ref().Slice(), Data: payload}}})

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "peer sent payload for non-existing transaction")
	})
}

func Test_protocol_handleTransactionPayloadQuery(t *testing.T) {
	payload := []byte("Hello, World!")

	t.Run("public TX", func(t *testing.T) {
		tx, _, _ := dag.CreateTestTransaction(0)
		t.Run("ok", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			graph := dag.NewMockDAG(ctrl)
			graph.EXPECT().Get(gomock.Any(), tx.Ref()).Return(tx, nil)
			payloadStore := dag.NewMockPayloadStore(ctrl)
			payloadStore.EXPECT().ReadPayload(gomock.Any(), gomock.Any()).Return(payload, nil)
			p := New(graph, payloadStore).(*protocol)

			conns := &grpc.StubConnectionList{PeerID: peer.ID}
			p.connectionList = conns

			err := p.Handle(peer, &Envelope{Message: &Envelope_TransactionPayloadQuery{&TransactionPayloadQuery{TransactionRef: tx.Ref().Slice()}}})

			assert.NoError(t, err)
			assertPayloadResponse(t, tx, payload, conns.Conn.SentMsgs[0])
		})
		t.Run("transaction not found", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			graph := dag.NewMockDAG(ctrl)
			graph.EXPECT().Get(gomock.Any(), tx.Ref()).Return(nil, nil)
			payloadStore := dag.NewMockPayloadStore(ctrl)
			p := New(graph, payloadStore).(*protocol)

			conns := &grpc.StubConnectionList{PeerID: peer.ID}
			p.connectionList = conns

			err := p.Handle(peer, &Envelope{Message: &Envelope_TransactionPayloadQuery{&TransactionPayloadQuery{TransactionRef: tx.Ref().Slice()}}})

			assert.NoError(t, err)
			assertEmptyPayloadResponse(t, tx, conns.Conn.SentMsgs[0])
		})
		t.Run("private transaction", func(t *testing.T) {

		})
	})
	t.Run("private TX", func(t *testing.T) {
		tx, _, _ := dag.CreateTestTransactionEx(0, hash.SHA256Sum(payload), [][]byte{{1, 2}, {3}})

		t.Run("connection is not authenticated", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			graph := dag.NewMockDAG(ctrl)
			graph.EXPECT().Get(gomock.Any(), tx.Ref()).Return(tx, nil)
			payloadStore := dag.NewMockPayloadStore(ctrl)
			p := New(graph, payloadStore).(*protocol)

			conns := &grpc.StubConnectionList{PeerID: peer.ID}
			p.connectionList = conns

			err := p.Handle(peer, &Envelope{Message: &Envelope_TransactionPayloadQuery{&TransactionPayloadQuery{TransactionRef: tx.Ref().Slice()}}})

			assert.NoError(t, err)
			assertEmptyPayloadResponse(t, tx, conns.Conn.SentMsgs[0])
		})
		t.Run("local node is not a participant in the TX", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			graph := dag.NewMockDAG(ctrl)
			graph.EXPECT().Get(gomock.Any(), tx.Ref()).Return(tx, nil)
			payloadStore := dag.NewMockPayloadStore(ctrl)
			p := New(graph, payloadStore).(*protocol)

			conns := &grpc.StubConnectionList{PeerID: peer.ID}
			p.connectionList = conns

			err := p.Handle(authenticatedPeer, &Envelope{Message: &Envelope_TransactionPayloadQuery{&TransactionPayloadQuery{TransactionRef: tx.Ref().Slice()}}})

			assert.NoError(t, err)
			assertEmptyPayloadResponse(t, tx, conns.Conn.SentMsgs[0])
		})

	})
}

func assertPayloadResponse(t *testing.T, tx dag.Transaction, payload []byte, raw interface{}) bool {
	envelope := raw.(*Envelope)
	return assert.Equal(t, TransactionPayload{
		TransactionRef: tx.Ref().Slice(),
		Data:           payload,
	}, *envelope.Message.(*Envelope_TransactionPayload).TransactionPayload)
}

func assertEmptyPayloadResponse(t *testing.T, tx dag.Transaction, raw interface{}) bool {
	return assertPayloadResponse(t, tx, nil, raw)
}
