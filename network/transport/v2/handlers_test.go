/*
 * Copyright (C) 2022 Nuts community
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

package v2

import (
	"context"
	"errors"
	"fmt"
	"math"
	"testing"

	"github.com/nuts-foundation/nuts-node/network/dag/tree"

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
	otherPeerDID, _   = did.ParseDID("did:nuts:other-peer")
	nodeDID, _        = did.ParseDID("did:nuts:node")
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
		assert.EqualError(t, err, "message not supported")
	})
	t.Run("handler error is returned as internal error", func(t *testing.T) {
		p, _ := newTestProtocol(t, nil)
		err := p.Handle(peer, &Envelope{Message: &Envelope_TransactionPayload{TransactionPayload: &TransactionPayload{TransactionRef: []byte{}}}})
		assert.EqualError(t, err, "internal error")
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

		mocks.State.EXPECT().GetTransaction(gomock.Any(), tx.Ref()).Return(tx, nil)
		mocks.State.EXPECT().WritePayload(gomock.Any(), tx, tx.PayloadHash(), payload)
		mocks.PayloadScheduler.EXPECT().Finished(tx.Ref()).Return(nil)

		err := p.Handle(peer, &Envelope{Message: &Envelope_TransactionPayload{&TransactionPayload{TransactionRef: tx.Ref().Slice(), Data: payload}}})

		assert.NoError(t, err)
	})

	t.Run("error - no tx ref", func(t *testing.T) {
		p, _ := newTestProtocol(t, nil)
		envelope := &Envelope{Message: &Envelope_TransactionPayload{&TransactionPayload{}}}
		err := p.handle(peer, envelope)

		assert.EqualError(t, err, "msg is missing transaction reference")
	})

	t.Run("error - no data", func(t *testing.T) {
		p, _ := newTestProtocol(t, nil)
		err := p.handle(peer, &Envelope{Message: &Envelope_TransactionPayload{&TransactionPayload{TransactionRef: []byte{1, 2, 3}}}})

		assert.EqualError(t, err, "peer does not have transaction payload (tx=0102030000000000000000000000000000000000000000000000000000000000)")
	})

	t.Run("error - payload does not match hash", func(t *testing.T) {
		p, mocks := newTestProtocol(t, nil)
		mocks.State.EXPECT().GetTransaction(gomock.Any(), tx.Ref()).Return(tx, nil)

		err := p.handle(peer, &Envelope{Message: &Envelope_TransactionPayload{&TransactionPayload{TransactionRef: tx.Ref().Slice(), Data: []byte("Hello, victim!")}}})

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "peer sent payload that doesn't match payload hash")
	})

	t.Run("error - tx not present", func(t *testing.T) {
		p, mocks := newTestProtocol(t, nil)
		mocks.State.EXPECT().GetTransaction(gomock.Any(), tx.Ref()).Return(nil, nil)

		err := p.handle(peer, &Envelope{Message: &Envelope_TransactionPayload{&TransactionPayload{TransactionRef: tx.Ref().Slice(), Data: payload}}})

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
			mocks.State.EXPECT().GetTransaction(gomock.Any(), tx.Ref()).Return(tx, nil)
			mocks.State.EXPECT().ReadPayload(gomock.Any(), gomock.Any()).Return(payload, nil)

			conns := &grpc.StubConnectionList{
				Conn: &grpc.StubConnection{PeerID: peer.ID},
			}
			p.connectionList = conns

			err := p.handle(peer, &Envelope{Message: &Envelope_TransactionPayloadQuery{&TransactionPayloadQuery{TransactionRef: tx.Ref().Slice()}}})

			assert.NoError(t, err)
			assertPayloadResponse(t, tx, payload, conns.Conn.SentMsgs[0])
		})

		t.Run("transaction not found", func(t *testing.T) {
			p, mocks := newTestProtocol(t, nil)
			mocks.State.EXPECT().GetTransaction(gomock.Any(), tx.Ref()).Return(nil, nil)

			conns := &grpc.StubConnectionList{
				Conn: &grpc.StubConnection{PeerID: peer.ID},
			}
			p.connectionList = conns

			err := p.handle(peer, &Envelope{Message: &Envelope_TransactionPayloadQuery{&TransactionPayloadQuery{TransactionRef: tx.Ref().Slice()}}})

			assert.NoError(t, err)
			assertEmptyPayloadResponse(t, tx, conns.Conn.SentMsgs[0])
		})
	})

	t.Run("private TX", func(t *testing.T) {
		tx, _, _ := dag.CreateTestTransactionEx(0, hash.SHA256Sum(payload), [][]byte{{1, 2}, {3}})
		keyDID, _ := did.ParseDIDURL("did:nuts:node#key1")
		didDocument := did.Document{
			KeyAgreement: []did.VerificationRelationship{
				{VerificationMethod: &did.VerificationMethod{ID: *keyDID}},
			},
		}

		t.Run("connection is not authenticated", func(t *testing.T) {
			p, mocks := newTestProtocol(t, nil)
			mocks.State.EXPECT().GetTransaction(gomock.Any(), tx.Ref()).Return(tx, nil)

			conns := &grpc.StubConnectionList{
				Conn: &grpc.StubConnection{PeerID: peer.ID},
			}
			p.connectionList = conns

			err := p.handle(peer, &Envelope{Message: &Envelope_TransactionPayloadQuery{&TransactionPayloadQuery{TransactionRef: tx.Ref().Slice()}}})

			assert.NoError(t, err)
			assertEmptyPayloadResponse(t, tx, conns.Conn.SentMsgs[0])
		})
		t.Run("local node is not a participant in the TX", func(t *testing.T) {
			p, mocks := newTestProtocol(t, nodeDID)
			mocks.State.EXPECT().GetTransaction(gomock.Any(), tx.Ref()).Return(tx, nil)
			mocks.DocResolver.EXPECT().Resolve(*nodeDID, nil).Return(&didDocument, nil, nil)
			mocks.Decrypter.EXPECT().Decrypt(keyDID.String(), gomock.Any()).Return(nil, errors.New("will return nil for PAL decryption")).Times(2)
			conns := &grpc.StubConnectionList{
				Conn: &grpc.StubConnection{PeerID: peer.ID},
			}
			p.connectionList = conns

			err := p.handle(authenticatedPeer, &Envelope{Message: &Envelope_TransactionPayloadQuery{&TransactionPayloadQuery{TransactionRef: tx.Ref().Slice()}}})

			assert.NoError(t, err)
			assertEmptyPayloadResponse(t, tx, conns.Conn.SentMsgs[0])
		})
		t.Run("decoding of the PAL header failed (nodeDID not set)", func(t *testing.T) {
			p, mocks := newTestProtocol(t, nil)
			mocks.State.EXPECT().GetTransaction(gomock.Any(), tx.Ref()).Return(tx, nil)
			conns := &grpc.StubConnectionList{
				Conn: &grpc.StubConnection{PeerID: peer.ID},
			}
			p.connectionList = conns

			err := p.handle(authenticatedPeer, &Envelope{Message: &Envelope_TransactionPayloadQuery{&TransactionPayloadQuery{TransactionRef: tx.Ref().Slice()}}})

			assert.NoError(t, err)
			assertEmptyPayloadResponse(t, tx, conns.Conn.SentMsgs[0])
		})
		t.Run("peer is not in PAL", func(t *testing.T) {
			p, mocks := newTestProtocol(t, nodeDID)
			mocks.State.EXPECT().GetTransaction(gomock.Any(), tx.Ref()).Return(tx, nil)
			mocks.DocResolver.EXPECT().Resolve(*nodeDID, nil).Return(&didDocument, nil, nil)
			mocks.Decrypter.EXPECT().Decrypt(keyDID.String(), gomock.Any()).Return([]byte(nodeDID.String()), nil)
			conns := &grpc.StubConnectionList{
				Conn: &grpc.StubConnection{PeerID: peer.ID},
			}
			p.connectionList = conns

			err := p.handle(authenticatedPeer, &Envelope{Message: &Envelope_TransactionPayloadQuery{&TransactionPayloadQuery{TransactionRef: tx.Ref().Slice()}}})

			assert.NoError(t, err)
			assertEmptyPayloadResponse(t, tx, conns.Conn.SentMsgs[0])
		})
		t.Run("ok", func(t *testing.T) {
			p, mocks := newTestProtocol(t, nodeDID)
			mocks.State.EXPECT().GetTransaction(gomock.Any(), tx.Ref()).Return(tx, nil)
			mocks.DocResolver.EXPECT().Resolve(*nodeDID, nil).Return(&didDocument, nil, nil)
			mocks.Decrypter.EXPECT().Decrypt(keyDID.String(), gomock.Any()).Return([]byte(peerDID.String()), nil)
			mocks.State.EXPECT().ReadPayload(context.Background(), tx.PayloadHash()).Return([]byte{}, nil)
			conns := &grpc.StubConnectionList{
				Conn: &grpc.StubConnection{PeerID: peer.ID},
			}
			p.connectionList = conns

			err := p.handle(authenticatedPeer, &Envelope{Message: &Envelope_TransactionPayloadQuery{&TransactionPayloadQuery{TransactionRef: tx.Ref().Slice()}}})

			assert.NoError(t, err)
			assertPayloadResponse(t, tx, []byte{}, conns.Conn.SentMsgs[0])
		})
	})
}

func TestProtocol_handleGossip(t *testing.T) {
	bytes := make([][]byte, 1)
	bytes[0] = hash.EmptyHash().Slice()
	xorLocal, xorPeer := hash.EmptyHash(), hash.FromSlice([]byte("test"))
	clockLocal, clockPeer := uint32(2), uint32(3)

	envelope := &Envelope{Message: &Envelope_Gossip{&Gossip{XOR: xorPeer.Slice(), LC: clockPeer, Transactions: bytes}}}

	t.Run("ok - xors match", func(t *testing.T) {
		p, mocks := newTestProtocol(t, nil)
		mocks.State.EXPECT().XOR(gomock.Any(), uint32(math.MaxUint32)).Return(xorPeer, clockPeer)

		err := p.handle(peer, envelope)

		assert.NoError(t, err)
	})

	t.Run("ok - new transaction ref makes xors equal", func(t *testing.T) {
		envelope := &Envelope{Message: &Envelope_Gossip{&Gossip{XOR: xorPeer.Slice(), LC: clockPeer, Transactions: [][]byte{xorPeer.Slice()}}}}

		p, mocks := newTestProtocol(t, nil)
		mocks.State.EXPECT().XOR(gomock.Any(), uint32(math.MaxUint32)).Return(xorLocal, clockLocal)
		mocks.State.EXPECT().IsPresent(gomock.Any(), xorPeer).Return(false, nil)
		mocks.Gossip.EXPECT().GossipReceived(peer.ID, xorPeer)

		mocks.Sender.EXPECT().sendTransactionListQuery(peer.ID, []hash.SHA256Hash{xorPeer})

		err := p.handle(peer, envelope)

		assert.NoError(t, err)
	})

	t.Run("ok - new transaction ref, xors still unequal", func(t *testing.T) {
		p, mocks := newTestProtocol(t, nil)
		mocks.State.EXPECT().XOR(gomock.Any(), uint32(math.MaxUint32)).Return(xorLocal, clockLocal)
		mocks.State.EXPECT().IsPresent(gomock.Any(), hash.EmptyHash()).Return(false, nil)
		mocks.Gossip.EXPECT().GossipReceived(peer.ID, hash.EmptyHash())
		mocks.Sender.EXPECT().sendState(peer.ID, xorLocal, clockLocal)

		mocks.Sender.EXPECT().sendTransactionListQuery(peer.ID, []hash.SHA256Hash{hash.FromSlice(bytes[0])})

		err := p.handle(peer, envelope)

		assert.NoError(t, err)
	})

	t.Run("ok - new transaction ref, peers lock is lower", func(t *testing.T) {
		envelope := &Envelope{Message: &Envelope_Gossip{&Gossip{XOR: xorPeer.Slice(), LC: clockLocal - 1, Transactions: [][]byte{xorPeer.Slice()}}}}

		p, mocks := newTestProtocol(t, nil)
		mocks.State.EXPECT().XOR(gomock.Any(), uint32(math.MaxUint32)).Return(xorLocal, clockLocal)
		mocks.State.EXPECT().IsPresent(gomock.Any(), xorPeer).Return(false, nil)
		mocks.Gossip.EXPECT().GossipReceived(peer.ID, xorPeer)

		mocks.Sender.EXPECT().sendTransactionListQuery(peer.ID, []hash.SHA256Hash{xorPeer})

		err := p.handle(peer, envelope)

		assert.NoError(t, err)
	})

	t.Run("error - new transaction ref, sendTransactionList fails", func(t *testing.T) {
		envelope := &Envelope{Message: &Envelope_Gossip{&Gossip{XOR: xorPeer.Slice(), LC: clockLocal - 1, Transactions: [][]byte{xorPeer.Slice()}}}}

		p, mocks := newTestProtocol(t, nil)
		mocks.State.EXPECT().XOR(gomock.Any(), uint32(math.MaxUint32)).Return(xorLocal, clockLocal)
		mocks.State.EXPECT().IsPresent(gomock.Any(), xorPeer).Return(false, nil)
		mocks.Gossip.EXPECT().GossipReceived(peer.ID, xorPeer)

		mocks.Sender.EXPECT().sendTransactionListQuery(peer.ID, []hash.SHA256Hash{xorPeer}).Return(errors.New("custom"))

		err := p.handle(peer, envelope)

		assert.EqualError(t, err, "custom")
	})

	t.Run("ok - existing transaction ref - sendState", func(t *testing.T) {
		p, mocks := newTestProtocol(t, nil)
		mocks.State.EXPECT().XOR(gomock.Any(), uint32(math.MaxUint32)).Return(xorLocal, clockPeer)
		mocks.State.EXPECT().IsPresent(gomock.Any(), hash.EmptyHash()).Return(true, nil)
		mocks.Sender.EXPECT().sendState(peer.ID, xorLocal, clockPeer).Return(nil)

		err := p.handle(peer, envelope)

		assert.NoError(t, err)
	})

	t.Run("error", func(t *testing.T) {
		p, mocks := newTestProtocol(t, nil)
		mocks.State.EXPECT().XOR(gomock.Any(), uint32(math.MaxUint32)).Return(xorLocal, clockLocal)
		mocks.State.EXPECT().IsPresent(gomock.Any(), hash.EmptyHash()).Return(false, errors.New("custom"))

		err := p.handle(peer, envelope)

		assert.EqualError(t, err, "failed to handle Gossip message: custom")
	})
}

func TestProtocol_handleTransactionList(t *testing.T) {
	tx, _, _ := dag.CreateTestTransaction(0)
	h1 := tx.Ref()
	data := tx.Data()
	payload := []byte{2}
	request := &Envelope_TransactionListQuery{TransactionListQuery: &TransactionListQuery{Refs: [][]byte{h1.Slice()}}}

	t.Run("ok", func(t *testing.T) {
		p, mocks := newTestProtocol(t, nil)
		conversation := p.cMan.startConversation(request)
		mocks.State.EXPECT().Add(context.Background(), tx, payload).Return(nil)

		err := p.handleTransactionList(peer, &Envelope_TransactionList{
			TransactionList: &TransactionList{
				ConversationID: conversation.conversationID.slice(),
				Transactions:   []*Transaction{{Data: data, Payload: payload}},
			},
		})

		assert.NoError(t, err)
	})

	t.Run("ok - duplicate", func(t *testing.T) {
		p, mocks := newTestProtocol(t, nil)
		conversation := p.cMan.startConversation(request)
		mocks.State.EXPECT().Add(context.Background(), tx, payload).Return(nil)

		err := p.handleTransactionList(peer, &Envelope_TransactionList{
			TransactionList: &TransactionList{
				ConversationID: conversation.conversationID.slice(),
				Transactions:   []*Transaction{{Data: data, Payload: payload}},
			},
		})

		assert.NoError(t, err)
	})

	t.Run("ok - missing prevs", func(t *testing.T) {
		p, mocks := newTestProtocol(t, nil)
		conversation := p.cMan.startConversation(request)
		mocks.State.EXPECT().Add(context.Background(), tx, payload).Return(dag.ErrPreviousTransactionMissing)
		mocks.State.EXPECT().XOR(context.Background(), uint32(math.MaxUint32)).Return(hash.FromSlice([]byte("stateXor")), uint32(7))
		mocks.Sender.EXPECT().sendState(peer.ID, hash.FromSlice([]byte("stateXor")), uint32(7))

		err := p.handleTransactionList(peer, &Envelope_TransactionList{
			TransactionList: &TransactionList{
				ConversationID: conversation.conversationID.slice(),
				Transactions:   []*Transaction{{Data: data, Payload: payload}},
			},
		})

		assert.NoError(t, err)
		assert.Nil(t, p.cMan.conversations[conversation.conversationID.String()])
	})

	t.Run("ok - conversation marked as done", func(t *testing.T) {
		p, mocks := newTestProtocol(t, nil)
		conversation := p.cMan.startConversation(request)
		conversation.set("refs", []hash.SHA256Hash{h1})
		mocks.State.EXPECT().Add(context.Background(), tx, payload).Return(nil)

		err := p.handleTransactionList(peer, &Envelope_TransactionList{
			TransactionList: &TransactionList{
				ConversationID: conversation.conversationID.slice(),
				Transactions:   []*Transaction{{Data: data, Payload: payload}},
				TotalMessages:  1,
				MessageNumber:  1,
			},
		})

		assert.NoError(t, err)
		assert.Nil(t, p.cMan.conversations[conversation.conversationID.String()])
	})

	t.Run("ok - conversation not marked as done", func(t *testing.T) {
		tx2, _, _ := dag.CreateTestTransaction(0)
		h2 := tx2.Ref()
		p, mocks := newTestProtocol(t, nil)
		conversation := p.cMan.startConversation(request)
		conversation.set("refs", []hash.SHA256Hash{h1, h2})
		mocks.State.EXPECT().Add(context.Background(), tx, payload).Return(nil)

		err := p.handleTransactionList(peer, &Envelope_TransactionList{
			TransactionList: &TransactionList{
				ConversationID: conversation.conversationID.slice(),
				Transactions:   []*Transaction{{Data: data, Payload: payload}},
				TotalMessages:  2,
				MessageNumber:  1,
			},
		})

		assert.NoError(t, err)
		assert.NotNil(t, p.cMan.conversations[conversation.conversationID.String()])
	})

	t.Run("error - State.Add failed", func(t *testing.T) {
		p, mocks := newTestProtocol(t, nil)
		conversation := p.cMan.startConversation(request)
		mocks.State.EXPECT().Add(context.Background(), tx, payload).Return(errors.New("custom"))

		err := p.handleTransactionList(peer, &Envelope_TransactionList{
			TransactionList: &TransactionList{
				ConversationID: conversation.conversationID.slice(),
				Transactions:   []*Transaction{{Data: data, Payload: payload}},
			},
		})

		assert.EqualError(t, err, fmt.Sprintf("unable to add received transaction to DAG (tx=%s): custom", tx.Ref().String()))
	})

	t.Run("error - missing payload for TX without PAL", func(t *testing.T) {
		p, _ := newTestProtocol(t, nil)
		conversation := p.cMan.startConversation(request)

		err := p.handleTransactionList(peer, &Envelope_TransactionList{
			TransactionList: &TransactionList{
				ConversationID: conversation.conversationID.slice(),
				Transactions:   []*Transaction{{Data: data}},
			},
		})

		assert.ErrorContains(t, err, "peer did not provide payload for transaction")
	})

	t.Run("error - invalid transaction", func(t *testing.T) {
		p, _ := newTestProtocol(t, nil)
		conversation := p.cMan.startConversation(request)

		err := p.handleTransactionList(peer, &Envelope_TransactionList{
			TransactionList: &TransactionList{
				ConversationID: conversation.conversationID.slice(),
				Transactions:   []*Transaction{{Data: []byte{1}}},
			},
		})

		assert.EqualError(t, err, "received transaction is invalid: unable to parse transaction: invalid compact serialization format: invalid number of segments")
	})

	t.Run("error - unknown conversationID", func(t *testing.T) {
		p, _ := newTestProtocol(t, nil)
		conversationID := newConversationID()

		err := p.handleTransactionList(peer, &Envelope_TransactionList{
			TransactionList: &TransactionList{
				ConversationID: conversationID.slice(),
			},
		})

		assert.EqualError(t, err, fmt.Sprintf("unknown or expired conversation (id=%s)", conversationID.String()))
	})
}

func TestProtocol_handleTransactionListQuery(t *testing.T) {
	conversationID := newConversationID()
	dagT1, _, _ := dag.CreateTestTransaction(1)
	dagT2, _, _ := dag.CreateTestTransaction(2, dagT1)
	h1 := dagT1.Ref()
	h2 := dagT2.Ref()

	t.Run("ok - send 2 transactions sorted on LC", func(t *testing.T) {
		p, mocks := newTestProtocol(t, nil)
		expectedTransactions := []*Transaction{
			{
				Data:    dagT1.Data(),
				Payload: []byte{1},
			},
			{
				Data:    dagT2.Data(),
				Payload: []byte{2},
			},
		}
		mocks.State.EXPECT().GetTransaction(context.Background(), h1).Return(dagT1, nil)
		mocks.State.EXPECT().GetTransaction(context.Background(), h2).Return(dagT2, nil)
		mocks.State.EXPECT().ReadPayload(context.Background(), dagT1.PayloadHash()).Return([]byte{1}, nil)
		mocks.State.EXPECT().ReadPayload(context.Background(), dagT2.PayloadHash()).Return([]byte{2}, nil)

		mocks.Sender.EXPECT().sendTransactionList(peer.ID, conversationID, expectedTransactions)

		err := p.Handle(peer, &Envelope{
			Message: &Envelope_TransactionListQuery{&TransactionListQuery{
				ConversationID: conversationID.slice(),
				Refs:           [][]byte{h2.Slice(), h1.Slice()}, // reverse order to test sorting
			}},
		})

		assert.NoError(t, err)
	})

	t.Run("ok - tx not present", func(t *testing.T) {
		p, mocks := newTestProtocol(t, nil)
		mocks.State.EXPECT().GetTransaction(context.Background(), h1).Return(nil, nil)
		mocks.State.EXPECT().GetTransaction(context.Background(), h2).Return(nil, nil)

		mocks.Sender.EXPECT().sendTransactionList(peer.ID, conversationID, gomock.Any())

		err := p.Handle(peer, &Envelope{
			Message: &Envelope_TransactionListQuery{&TransactionListQuery{
				ConversationID: conversationID.slice(),
				Refs:           [][]byte{h1.Slice(), h2.Slice()},
			}},
		})

		assert.NoError(t, err)
	})

	t.Run("error - on State.GetTransaction", func(t *testing.T) {
		p, mocks := newTestProtocol(t, nil)
		mocks.State.EXPECT().GetTransaction(context.Background(), h1).Return(nil, errors.New("custom"))

		err := p.Handle(peer, &Envelope{
			Message: &Envelope_TransactionListQuery{&TransactionListQuery{
				ConversationID: conversationID.slice(),
				Refs:           [][]byte{h1.Slice()}, // reverse order to test sorting
			}},
		})

		assert.Error(t, err)
	})

	t.Run("error - on State.ReadPayload", func(t *testing.T) {
		p, mocks := newTestProtocol(t, nil)
		mocks.State.EXPECT().GetTransaction(context.Background(), h1).Return(dagT1, nil)
		mocks.State.EXPECT().ReadPayload(context.Background(), dagT1.PayloadHash()).Return(nil, errors.New("custom"))

		err := p.Handle(peer, &Envelope{
			Message: &Envelope_TransactionListQuery{&TransactionListQuery{
				ConversationID: conversationID.slice(),
				Refs:           [][]byte{h1.Slice()}, // reverse order to test sorting
			}},
		})

		assert.Error(t, err)
	})

	t.Run("ok - missing payload", func(t *testing.T) {
		p, mocks := newTestProtocol(t, nil)
		mocks.State.EXPECT().GetTransaction(context.Background(), h1).Return(dagT1, nil)
		mocks.State.EXPECT().GetTransaction(context.Background(), h2).Return(dagT2, nil)
		mocks.State.EXPECT().ReadPayload(context.Background(), dagT1.PayloadHash()).Return(nil, nil)

		err := p.handle(peer, &Envelope{
			Message: &Envelope_TransactionListQuery{&TransactionListQuery{
				ConversationID: conversationID.slice(),
				Refs:           [][]byte{h2.Slice(), h1.Slice()}, // reverse order to test sorting
			}},
		})

		assert.ErrorContains(t, err, "transaction is missing payload")
	})

	t.Run("ok - empty request", func(t *testing.T) {
		p, _ := newTestProtocol(t, nil)

		err := p.Handle(peer, &Envelope{
			Message: &Envelope_TransactionListQuery{&TransactionListQuery{
				ConversationID: conversationID.slice(),
			}},
		})

		assert.NoError(t, err)
	})
}

func TestProtocol_handleTransactionRangeQuery(t *testing.T) {
	payload := []byte("Hello, World!")
	tx1, _, _ := dag.CreateTestTransaction(0)
	tx2, _, _ := dag.CreateTestTransaction(1, tx1)
	lcStart := uint32(1)
	lcEnd := uint32(5)

	t.Run("ok", func(t *testing.T) {
		p, mocks := newTestProtocol(t, nil)

		mocks.State.EXPECT().FindBetweenLC(gomock.Any(), lcStart, lcEnd).Return([]dag.Transaction{tx1, tx2}, nil)
		mocks.State.EXPECT().ReadPayload(gomock.Any(), tx1.PayloadHash()).Return(payload, nil)
		mocks.State.EXPECT().ReadPayload(gomock.Any(), tx2.PayloadHash()).Return(payload, nil)
		mocks.Sender.EXPECT().sendTransactionList(peer.ID, gomock.Any(), gomock.Any())

		msg := &Envelope_TransactionRangeQuery{&TransactionRangeQuery{
			Start: lcStart,
			End:   lcEnd,
		}}
		p.cMan.startConversation(msg)
		err := p.Handle(peer, &Envelope{Message: msg})

		assert.NoError(t, err)
	})
	t.Run("error - invalid range", func(t *testing.T) {
		p, _ := newTestProtocol(t, nil)

		msg := &Envelope_TransactionRangeQuery{&TransactionRangeQuery{
			Start: 1,
			End:   1,
		}}
		p.cMan.startConversation(msg)
		err := p.handle(peer, &Envelope{Message: msg})

		assert.EqualError(t, err, "invalid range query")
	})
	t.Run("error - DAG reading error", func(t *testing.T) {
		p, mocks := newTestProtocol(t, nil)
		mocks.State.EXPECT().FindBetweenLC(gomock.Any(), lcStart, lcEnd).Return(nil, errors.New("failure"))
		msg := &Envelope_TransactionRangeQuery{&TransactionRangeQuery{
			Start: lcStart,
			End:   lcEnd,
		}}
		p.cMan.startConversation(msg)
		err := p.Handle(peer, &Envelope{Message: msg})

		assert.Error(t, err)
	})
}

func TestProtocol_handleState(t *testing.T) {
	peerXor, localXor := hash.FromSlice([]byte("peer")), hash.FromSlice([]byte("local"))
	peerClock, localClock := uint32(6), uint32(5)

	t.Run("ok - xors are the same", func(t *testing.T) {
		msg := &Envelope_State{State: &State{LC: peerClock, XOR: peerXor.Slice()}}
		p, mocks := newTestProtocol(t, nil)
		mocks.State.EXPECT().XOR(context.Background(), uint32(math.MaxUint32)).Return(peerXor, localClock)

		err := p.Handle(peer, &Envelope{Message: msg})

		assert.NoError(t, err)
	})

	t.Run("ok - TransactionSet response", func(t *testing.T) {
		msg := &Envelope_State{State: &State{LC: peerClock, XOR: peerXor.Slice()}}
		iblt := *tree.NewIblt(10)
		p, mocks := newTestProtocol(t, nil)
		conversation := p.cMan.startConversation(msg)
		mocks.State.EXPECT().XOR(context.Background(), uint32(math.MaxUint32)).Return(localXor, localClock)
		mocks.State.EXPECT().IBLT(context.Background(), peerClock).Return(iblt, uint32(0))
		mocks.Sender.EXPECT().sendTransactionSet(peer.ID, conversation.conversationID, peerClock, localClock, iblt)

		err := p.Handle(peer, &Envelope{Message: msg})

		assert.NoError(t, err)
	})
}

func TestProtocol_handleTransactionSet(t *testing.T) {
	requestLC := uint32(3)
	request := &Envelope_State{State: &State{LC: requestLC, XOR: hash.FromSlice([]byte("requestXOR")).Slice()}}

	emptyIblt := tree.NewIblt(10)
	emptyIbltBytes, _ := emptyIblt.MarshalBinary()

	hash1, _, _ := dag.CreateTestTransaction(1)
	oneHashIblt := emptyIblt.Clone().(*tree.Iblt)
	oneHashIblt.Insert(hash1.Ref())
	oneHashIbltBytes, _ := oneHashIblt.MarshalBinary()

	t.Run("ok - decode success, peer is behind", func(t *testing.T) {
		peerLC := requestLC - 1
		localLC := requestLC
		p, mocks := newTestProtocol(t, nil)
		conversation := p.cMan.startConversation(request)
		mocks.State.EXPECT().IBLT(context.Background(), peerLC).Return(*oneHashIblt, dag.PageSize-1)
		mocks.State.EXPECT().XOR(context.Background(), uint32(math.MaxUint32)).Return(hash.FromSlice([]byte("ignored")), localLC)

		err := p.handleTransactionSet(peer, &Envelope_TransactionSet{
			TransactionSet: &TransactionSet{ConversationID: conversation.conversationID.slice(), LCReq: requestLC, LC: peerLC, IBLT: emptyIbltBytes},
		})

		assert.NoError(t, err)
	})

	t.Run("ok - decode success comparing historic pages, request missing tx and next page", func(t *testing.T) {
		localLC := requestLC + dag.PageSize
		peerLC := requestLC + dag.PageSize*3
		p, mocks := newTestProtocol(t, nil)
		conversation := p.cMan.startConversation(request)
		mocks.State.EXPECT().IBLT(context.Background(), requestLC).Return(*emptyIblt, dag.PageSize-1)
		mocks.Sender.EXPECT().sendTransactionListQuery(peer.ID, []hash.SHA256Hash{hash1.Ref()}).Return(nil)
		mocks.State.EXPECT().XOR(context.Background(), uint32(math.MaxUint32)).Return(hash.FromSlice([]byte("ignored")), localLC)
		mocks.Sender.EXPECT().sendTransactionRangeQuery(peer.ID, dag.PageSize, 2*dag.PageSize).Return(nil)

		err := p.handleTransactionSet(peer, &Envelope_TransactionSet{
			TransactionSet: &TransactionSet{ConversationID: conversation.conversationID.slice(), LCReq: requestLC, LC: peerLC, IBLT: oneHashIbltBytes},
		})

		assert.NoError(t, err)
	})

	t.Run("ok - decode success comparing dag state, request missing tx and DAG sync", func(t *testing.T) {
		peerLC := requestLC + dag.PageSize
		p, mocks := newTestProtocol(t, nil)
		conversation := p.cMan.startConversation(request)
		mocks.State.EXPECT().IBLT(context.Background(), requestLC).Return(*emptyIblt, dag.PageSize-1)
		mocks.Sender.EXPECT().sendTransactionListQuery(peer.ID, []hash.SHA256Hash{hash1.Ref()}).Return(nil)
		mocks.State.EXPECT().XOR(context.Background(), uint32(math.MaxUint32)).Return(hash.FromSlice([]byte("ignored")), requestLC)
		mocks.Sender.EXPECT().sendTransactionRangeQuery(peer.ID, dag.PageSize, uint32(math.MaxUint32)).Return(nil)

		err := p.handleTransactionSet(peer, &Envelope_TransactionSet{
			TransactionSet: &TransactionSet{ConversationID: conversation.conversationID.slice(), LCReq: requestLC, LC: peerLC, IBLT: oneHashIbltBytes},
		})

		assert.NoError(t, err)
	})

	t.Run("ok - decode fails, new state msg", func(t *testing.T) {
		localXor := hash.FromSlice([]byte("localXOR"))
		page1RequestLC := dag.PageSize + requestLC
		request := &Envelope_State{State: &State{LC: page1RequestLC, XOR: hash.FromSlice([]byte("requestXOR")).Slice()}}
		conflictingIblt := emptyIblt.Clone().(*tree.Iblt)
		conflictingIblt.Insert(hash1.Ref())
		conflictingIblt.Insert(hash1.Ref())
		p, mocks := newTestProtocol(t, nil)
		conversation := p.cMan.startConversation(request)
		mocks.State.EXPECT().IBLT(context.Background(), page1RequestLC).Return(*conflictingIblt, dag.PageSize-1)
		mocks.State.EXPECT().XOR(context.Background(), uint32(math.MaxUint32)).Return(localXor, uint32(0))
		mocks.Sender.EXPECT().sendState(peer.ID, localXor, dag.PageSize-1).Return(nil)

		err := p.handleTransactionSet(peer, &Envelope_TransactionSet{
			TransactionSet: &TransactionSet{ConversationID: conversation.conversationID.slice(), LCReq: page1RequestLC, LC: page1RequestLC, IBLT: emptyIbltBytes},
		})

		assert.NoError(t, err)
	})

	t.Run("ok - decode fails, request first page", func(t *testing.T) {
		conflictingIblt := emptyIblt.Clone().(*tree.Iblt)
		conflictingIblt.Insert(hash1.Ref())
		conflictingIblt.Insert(hash1.Ref())
		p, mocks := newTestProtocol(t, nil)
		conversation := p.cMan.startConversation(request)
		mocks.State.EXPECT().IBLT(context.Background(), requestLC).Return(*conflictingIblt, dag.PageSize-1)
		mocks.Sender.EXPECT().sendTransactionRangeQuery(peer.ID, uint32(0), dag.PageSize).Return(nil)

		err := p.handleTransactionSet(peer, &Envelope_TransactionSet{
			TransactionSet: &TransactionSet{ConversationID: conversation.conversationID.slice(), LCReq: requestLC, LC: requestLC, IBLT: emptyIbltBytes},
		})

		assert.NoError(t, err)
	})

	t.Run("error - decode fails", func(t *testing.T) {
		//TODO?? requires mocking of tree.Iblt or access to unexported fields
	})

	t.Run("ok - conversation marked as done", func(t *testing.T) {
		// TODO: re-enable with TX range check
		t.Skip()
		p, mocks := newTestProtocol(t, nil)
		conversation := p.cMan.startConversation(request)
		mocks.State.EXPECT().IBLT(context.Background(), requestLC).Return(*emptyIblt, dag.PageSize-1)

		response := &Envelope_TransactionSet{
			TransactionSet: &TransactionSet{ConversationID: conversation.conversationID.slice(), LCReq: requestLC, LC: requestLC, IBLT: emptyIbltBytes},
		}

		err := p.handleTransactionSet(peer, response)

		assert.NoError(t, err)
		assert.Nil(t, p.cMan.conversations[conversation.conversationID.String()])
	})

	t.Run("error - unknown conversationID", func(t *testing.T) {
		p, _ := newTestProtocol(t, nil)
		conversationID := newConversationID()

		err := p.handleTransactionSet(peer, &Envelope_TransactionSet{
			TransactionSet: &TransactionSet{
				ConversationID: conversationID.slice(),
			},
		})

		assert.EqualError(t, err, fmt.Sprintf("unknown or expired conversation (id=%s)", conversationID.String()))
	})

	t.Run("error - iblt subtract fails", func(t *testing.T) {
		p, mocks := newTestProtocol(t, nil)
		conversation := p.cMan.startConversation(request)
		mocks.State.EXPECT().IBLT(context.Background(), requestLC).Return(*tree.NewIblt(20), dag.PageSize-1)

		emptyIbltBytes, _ := emptyIblt.MarshalBinary()

		response := &Envelope_TransactionSet{
			TransactionSet: &TransactionSet{ConversationID: conversation.conversationID.slice(), LCReq: requestLC, LC: requestLC, IBLT: emptyIbltBytes},
		}

		err := p.handleTransactionSet(peer, response)

		assert.EqualError(t, err, "number of buckets do not match, expected (20) got (10)")
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
