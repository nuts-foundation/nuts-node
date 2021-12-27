package v2

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/network/transport/grpc"
	"github.com/stretchr/testify/assert"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/network/transport"
)

var (
	peer = transport.Peer{
		ID:      "abc",
		Address: "abc:5555",
	}
	peerDID, _        = did.ParseDID("did:nuts:peer")
	authenticatedPeer = transport.Peer{
		ID:      "abc",
		Address: "abc:5555",
		NodeDID: *peerDID,
	}
)

func TestProtocol_handle(t *testing.T) {
	t.Run("no handleable messages", func(t *testing.T) {
		p, _ := newTestProtocol(t, nil)
		err := p.Handle(peer, &Envelope{})
		assert.EqualError(t, err, "envelope doesn't contain any (handleable) messages")
	})
}

func TestProtocol_handleHello(t *testing.T) {
	proto, _ := newTestProtocol(t, nil)
	err := proto.Handle(peer, &Envelope{Message: &Envelope_Hello{}})

	assert.NoError(t, err)
}

func TestProtocol_handleTransactionPayload(t *testing.T) {
	payload := []byte("Hello, World!")
	tx, _, _ := dag.CreateTestTransactionEx(0, hash.SHA256Sum(payload), nil)

	t.Run("ok", func(t *testing.T) {
		p, mocks := newTestProtocol(t, nil)

		mocks.Graph.EXPECT().Get(gomock.Any(), tx.Ref()).Return(tx, nil)
		mocks.PayloadStore.EXPECT().WritePayload(gomock.Any(), tx.PayloadHash(), payload)

		err := p.Handle(peer, &Envelope{Message: &Envelope_TransactionPayload{&TransactionPayload{TransactionRef: tx.Ref().Slice(), Data: payload}}})

		assert.NoError(t, err)
	})

	t.Run("error - no tx ref", func(t *testing.T) {
		p, _ := newTestProtocol(t, nil)
		envelope := &Envelope{Message: &Envelope_TransactionPayload{&TransactionPayload{}}}
		err := p.Handle(peer, envelope)

		assert.EqualError(t, err, "message is missing transaction reference")
	})

	t.Run("error - no data", func(t *testing.T) {
		p, _ := newTestProtocol(t, nil)
		err := p.Handle(peer, &Envelope{Message: &Envelope_TransactionPayload{&TransactionPayload{TransactionRef: []byte{1, 2, 3}}}})

		assert.EqualError(t, err, "peer does not have transaction payload (tx=0102030000000000000000000000000000000000000000000000000000000000)")
	})

	t.Run("error - payload does not match hash", func(t *testing.T) {
		p, mocks := newTestProtocol(t, nil)
		mocks.Graph.EXPECT().Get(gomock.Any(), tx.Ref()).Return(tx, nil)

		err := p.Handle(peer, &Envelope{Message: &Envelope_TransactionPayload{&TransactionPayload{TransactionRef: tx.Ref().Slice(), Data: []byte("Hello, victim!")}}})

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "peer sent payload that doesn't match payload hash")
	})

	t.Run("error - tx not present", func(t *testing.T) {
		p, mocks := newTestProtocol(t, nil)
		mocks.Graph.EXPECT().Get(gomock.Any(), tx.Ref()).Return(nil, nil)

		err := p.Handle(peer, &Envelope{Message: &Envelope_TransactionPayload{&TransactionPayload{TransactionRef: tx.Ref().Slice(), Data: payload}}})

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "peer sent payload for non-existing transaction")
	})
}

func TestProtocol_handleTransactionPayloadQuery(t *testing.T) {
	payload := []byte("Hello, World!")

	t.Run("public TX", func(t *testing.T) {
		tx, _, _ := dag.CreateTestTransaction(0)

		t.Run("ok", func(t *testing.T) {
			p, mocks := newTestProtocol(t, nil)
			mocks.Graph.EXPECT().Get(gomock.Any(), tx.Ref()).Return(tx, nil)
			mocks.PayloadStore.EXPECT().ReadPayload(gomock.Any(), gomock.Any()).Return(payload, nil)

			conns := &grpc.StubConnectionList{
				Conn: &grpc.StubConnection{PeerID: peer.ID},
			}
			p.connectionList = conns

			err := p.Handle(peer, &Envelope{Message: &Envelope_TransactionPayloadQuery{&TransactionPayloadQuery{TransactionRef: tx.Ref().Slice()}}})

			assert.NoError(t, err)
			assertPayloadResponse(t, tx, payload, conns.Conn.SentMsgs[0])
		})

		t.Run("transaction not found", func(t *testing.T) {
			p, mocks := newTestProtocol(t, nil)
			mocks.Graph.EXPECT().Get(gomock.Any(), tx.Ref()).Return(nil, nil)

			conns := &grpc.StubConnectionList{
				Conn: &grpc.StubConnection{PeerID: peer.ID},
			}
			p.connectionList = conns

			err := p.Handle(peer, &Envelope{Message: &Envelope_TransactionPayloadQuery{&TransactionPayloadQuery{TransactionRef: tx.Ref().Slice()}}})

			assert.NoError(t, err)
			assertEmptyPayloadResponse(t, tx, conns.Conn.SentMsgs[0])
		})

		t.Run("private transaction", func(t *testing.T) {
			// @TODO
		})
	})

	t.Run("private TX", func(t *testing.T) {
		tx, _, _ := dag.CreateTestTransactionEx(0, hash.SHA256Sum(payload), [][]byte{{1, 2}, {3}})

		t.Run("connection is not authenticated", func(t *testing.T) {
			p, mocks := newTestProtocol(t, nil)
			mocks.Graph.EXPECT().Get(gomock.Any(), tx.Ref()).Return(tx, nil)

			conns := &grpc.StubConnectionList{
				Conn: &grpc.StubConnection{PeerID: peer.ID},
			}
			p.connectionList = conns

			err := p.Handle(peer, &Envelope{Message: &Envelope_TransactionPayloadQuery{&TransactionPayloadQuery{TransactionRef: tx.Ref().Slice()}}})

			assert.NoError(t, err)
			assertEmptyPayloadResponse(t, tx, conns.Conn.SentMsgs[0])
		})
		t.Run("local node is not a participant in the TX", func(t *testing.T) {
			p, mocks := newTestProtocol(t, nil)
			mocks.Graph.EXPECT().Get(gomock.Any(), tx.Ref()).Return(tx, nil)

			conns := &grpc.StubConnectionList{
				Conn: &grpc.StubConnection{PeerID: peer.ID},
			}
			p.connectionList = conns

			err := p.Handle(authenticatedPeer, &Envelope{Message: &Envelope_TransactionPayloadQuery{&TransactionPayloadQuery{TransactionRef: tx.Ref().Slice()}}})

			assert.NoError(t, err)
			assertEmptyPayloadResponse(t, tx, conns.Conn.SentMsgs[0])
		})

	})
}

func assertPayloadResponse(t *testing.T, tx dag.Transaction, payload []byte, raw interface{}) bool {
	envelope := raw.(*Envelope)

	return assert.Equal(t, &TransactionPayload{
		TransactionRef: tx.Ref().Slice(),
		Data:           payload,
	}, envelope.Message.(*Envelope_TransactionPayload).TransactionPayload)
}

func assertEmptyPayloadResponse(t *testing.T, tx dag.Transaction, raw interface{}) bool {
	return assertPayloadResponse(t, tx, nil, raw)
}
