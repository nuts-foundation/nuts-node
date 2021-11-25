package v2

import (
	"errors"
	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/stretchr/testify/assert"
	"testing"
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

func Test_protocol_logHandlerError(t *testing.T) {
	handleErrorLogger(&TransactionPayload{}, peer, errors.New("failure"))
}

func Test_protocol_handle(t *testing.T) {
	t.Run("no handleable messages", func(t *testing.T) {
		p := New(nil, nil).(*protocol)
		p.handle(peer, &Envelope{}, nil)
	})
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

		var reply replyCaptor
		var err handleErrorCaptor
		err.capture(t)

		p.handle(peer, &Envelope{Message: &Envelope_TransactionPayload{&TransactionPayload{TransactionRef: tx.Ref().Slice(), Data: payload}}}, reply.capture())

		assert.NoError(t, err.value)
	})
	t.Run("error - no tx ref", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		graph := dag.NewMockDAG(ctrl)
		payloadStore := dag.NewMockPayloadStore(ctrl)
		p := New(graph, payloadStore).(*protocol)

		var reply replyCaptor
		var err handleErrorCaptor
		err.capture(t)

		envelope := &Envelope{Message: &Envelope_TransactionPayload{&TransactionPayload{}}}
		p.handle(peer, envelope, reply.capture())

		assert.EqualError(t, err, "message is missing transaction reference")
		assert.Nil(t, reply.value)
	})
	t.Run("error - no data", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		graph := dag.NewMockDAG(ctrl)
		payloadStore := dag.NewMockPayloadStore(ctrl)
		p := New(graph, payloadStore).(*protocol)

		var reply replyCaptor
		var err handleErrorCaptor
		err.capture(t)

		p.handle(peer, &Envelope{Message: &Envelope_TransactionPayload{&TransactionPayload{TransactionRef: []byte{1, 2, 3}}}}, reply.capture())

		assert.EqualError(t, err, "peer does not have transaction payload (tx=0102030000000000000000000000000000000000000000000000000000000000)")
		assert.Nil(t, reply.value)
	})
	t.Run("error - payload does not match hash", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		graph := dag.NewMockDAG(ctrl)
		graph.EXPECT().Get(gomock.Any(), tx.Ref()).Return(tx, nil)
		payloadStore := dag.NewMockPayloadStore(ctrl)
		p := New(graph, payloadStore).(*protocol)

		var reply replyCaptor
		var err handleErrorCaptor
		err.capture(t)

		p.handle(peer, &Envelope{Message: &Envelope_TransactionPayload{&TransactionPayload{TransactionRef: tx.Ref().Slice(), Data: []byte("Hello, victim!")}}}, reply.capture())

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "peer sent payload that doesn't match payload hash")
	})
	t.Run("error - tx not present", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		graph := dag.NewMockDAG(ctrl)
		graph.EXPECT().Get(gomock.Any(), tx.Ref()).Return(nil, nil)
		payloadStore := dag.NewMockPayloadStore(ctrl)
		p := New(graph, payloadStore).(*protocol)

		var reply replyCaptor
		var err handleErrorCaptor
		err.capture(t)

		p.handle(peer, &Envelope{Message: &Envelope_TransactionPayload{&TransactionPayload{TransactionRef: tx.Ref().Slice(), Data: payload}}}, reply.capture())

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

			var reply replyCaptor
			var err handleErrorCaptor
			err.capture(t)

			p.handle(peer, &Envelope{Message: &Envelope_TransactionPayloadQuery{&TransactionPayloadQuery{TransactionRef: tx.Ref().Slice()}}}, reply.capture())

			assert.NoError(t, err.value)
			assertPayloadResponse(t, tx, payload, reply)
		})
		t.Run("transaction not found", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			graph := dag.NewMockDAG(ctrl)
			graph.EXPECT().Get(gomock.Any(), tx.Ref()).Return(nil, nil)
			payloadStore := dag.NewMockPayloadStore(ctrl)
			p := New(graph, payloadStore).(*protocol)

			var reply replyCaptor
			var err handleErrorCaptor
			err.capture(t)

			p.handle(peer, &Envelope{Message: &Envelope_TransactionPayloadQuery{&TransactionPayloadQuery{TransactionRef: tx.Ref().Slice()}}}, reply.capture())

			assert.NoError(t, err.value)
			assertEmptyPayloadResponse(t, tx, reply)
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

			var reply replyCaptor
			var err handleErrorCaptor
			err.capture(t)

			p.handle(peer, &Envelope{Message: &Envelope_TransactionPayloadQuery{&TransactionPayloadQuery{TransactionRef: tx.Ref().Slice()}}}, reply.capture())

			assert.NoError(t, err.value)
			assertEmptyPayloadResponse(t, tx, reply)
		})
		t.Run("local node is not a participant in the TX", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			graph := dag.NewMockDAG(ctrl)
			graph.EXPECT().Get(gomock.Any(), tx.Ref()).Return(tx, nil)
			payloadStore := dag.NewMockPayloadStore(ctrl)
			p := New(graph, payloadStore).(*protocol)

			var reply replyCaptor
			var err handleErrorCaptor
			err.capture(t)

			p.handle(authenticatedPeer, &Envelope{Message: &Envelope_TransactionPayloadQuery{&TransactionPayloadQuery{TransactionRef: tx.Ref().Slice()}}}, reply.capture())

			assert.NoError(t, err.value)
			assertEmptyPayloadResponse(t, tx, reply)
		})

	})
}

func assertPayloadResponse(t *testing.T, tx dag.Transaction, payload []byte, reply replyCaptor) bool {
	return assert.Equal(t, TransactionPayload{
		TransactionRef: tx.Ref().Slice(),
		Data:           payload,
	}, *reply.value.(*Envelope_TransactionPayload).TransactionPayload)
}

func assertEmptyPayloadResponse(t *testing.T, tx dag.Transaction, reply replyCaptor) bool {
	return assertPayloadResponse(t, tx, nil, reply)
}

type handleErrorCaptor struct {
	value error
}

func (s handleErrorCaptor) Error() string {
	if s.value == nil {
		return ""
	}
	return s.value.Error()
}

func (s *handleErrorCaptor) capture(t *testing.T) {
	old := handleErrorLogger
	t.Cleanup(func() {
		handleErrorLogger = old
	})
	handleErrorLogger = func(_ interface{}, _ transport.Peer, err error) {
		s.value = err
	}
}

type replyCaptor struct {
	value isEnvelope_Message
}

func (s *replyCaptor) capture() func(msg isEnvelope_Message) error {
	return func(msg isEnvelope_Message) error {
		s.value = msg.(isEnvelope_Message)
		return nil
	}
}
