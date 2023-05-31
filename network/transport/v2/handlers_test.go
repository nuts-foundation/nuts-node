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
	peerDID, _      = did.ParseDID("did:nuts:peer")
	otherPeerDID, _ = did.ParseDID("did:nuts:other-peer")
	nodeDID, _      = did.ParseDID("did:nuts:node")
	peer            = transport.Peer{
		ID:            "abc",
		Address:       "abc:5555",
		NodeDID:       *peerDID,
		Authenticated: false,
	}
	connection        = grpc.NewStubConnection(peer)
	authenticatedPeer = transport.Peer{
		ID:            "abc",
		Address:       "abc:5555",
		NodeDID:       *peerDID,
		Authenticated: true,
	}
)

func TestProtocol_handle(t *testing.T) {
	t.Run("no handleable messages", func(t *testing.T) {
		p, _ := newTestProtocol(t, nil)
		err := p.Handle(connection, &Envelope{})
		assert.EqualError(t, err, "message not supported")
	})
}

func TestProtocol_handleTransactionPayload(t *testing.T) {
	payload := []byte("Hello, World!")
	tx, _, _ := dag.CreateTestTransactionEx(0, hash.SHA256Sum(payload), nil)

	t.Run("ok", func(t *testing.T) {
		p, mocks := newTestProtocol(t, nil)

		mocks.State.EXPECT().GetTransaction(gomock.Any(), tx.Ref()).Return(tx, nil)
		mocks.State.EXPECT().WritePayload(context.Background(), tx, tx.PayloadHash(), payload)
		mocks.PayloadScheduler.EXPECT().Finished(tx.Ref()).Return(nil)

		err := p.handleTransactionPayload(context.Background(), connection, &Envelope{Message: &Envelope_TransactionPayload{&TransactionPayload{TransactionRef: tx.Ref().Slice(), Data: payload}}})

		assert.NoError(t, err)
	})

	t.Run("error - no tx ref", func(t *testing.T) {
		p, _ := newTestProtocol(t, nil)
		envelope := &Envelope{Message: &Envelope_TransactionPayload{&TransactionPayload{}}}
		err := p.handleTransactionPayload(context.Background(), connection, envelope)

		assert.EqualError(t, err, "msg is missing transaction reference")
	})

	t.Run("error - no data", func(t *testing.T) {
		p, _ := newTestProtocol(t, nil)
		err := p.handleTransactionPayload(context.Background(), connection, &Envelope{Message: &Envelope_TransactionPayload{&TransactionPayload{TransactionRef: []byte{1, 2, 3}}}})

		assert.EqualError(t, err, "peer does not have transaction payload (tx=0102030000000000000000000000000000000000000000000000000000000000)")
	})

	t.Run("error - payload does not match hash", func(t *testing.T) {
		p, mocks := newTestProtocol(t, nil)
		mocks.State.EXPECT().GetTransaction(gomock.Any(), tx.Ref()).Return(tx, nil)

		err := p.handleTransactionPayload(context.Background(), connection, &Envelope{Message: &Envelope_TransactionPayload{&TransactionPayload{TransactionRef: tx.Ref().Slice(), Data: []byte("Hello, victim!")}}})

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "peer sent payload that doesn't match payload hash")
	})

	t.Run("error - tx not present", func(t *testing.T) {
		p, mocks := newTestProtocol(t, nil)
		mocks.State.EXPECT().GetTransaction(gomock.Any(), tx.Ref()).Return(nil, dag.ErrTransactionNotFound)

		err := p.handleTransactionPayload(context.Background(), connection, &Envelope{Message: &Envelope_TransactionPayload{&TransactionPayload{TransactionRef: tx.Ref().Slice(), Data: payload}}})

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

			conns := grpc.NewStubConnectionList(peer)
			p.connectionList = conns

			err := p.handleTransactionPayloadQuery(context.Background(), conns.Conn, &Envelope{Message: &Envelope_TransactionPayloadQuery{&TransactionPayloadQuery{TransactionRef: tx.Ref().Slice()}}})

			assert.NoError(t, err)
			assertPayloadResponse(t, tx, payload, conns.Conn.SentMsgs[0])
		})

		t.Run("transaction not found", func(t *testing.T) {
			p, mocks := newTestProtocol(t, nil)
			mocks.State.EXPECT().GetTransaction(gomock.Any(), tx.Ref()).Return(nil, dag.ErrTransactionNotFound)

			conns := grpc.NewStubConnectionList(peer)
			p.connectionList = conns

			err := p.handleTransactionPayloadQuery(context.Background(), conns.Conn, &Envelope{Message: &Envelope_TransactionPayloadQuery{&TransactionPayloadQuery{TransactionRef: tx.Ref().Slice()}}})

			assert.NoError(t, err)
			assertEmptyPayloadResponse(t, tx, conns.Conn.SentMsgs[0])
		})
	})

	t.Run("private TX", func(t *testing.T) {
		ctx := context.Background()
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

			conns := grpc.NewStubConnectionList(peer)
			p.connectionList = conns

			err := p.handleTransactionPayloadQuery(ctx, conns.Conn, &Envelope{Message: &Envelope_TransactionPayloadQuery{&TransactionPayloadQuery{TransactionRef: tx.Ref().Slice()}}})

			assert.NoError(t, err)
			assertEmptyPayloadResponse(t, tx, conns.Conn.SentMsgs[0])
		})
		t.Run("local node is not a participant in the TX", func(t *testing.T) {
			p, mocks := newTestProtocol(t, nodeDID)
			mocks.State.EXPECT().GetTransaction(gomock.Any(), tx.Ref()).Return(tx, nil)
			mocks.DocResolver.EXPECT().Resolve(*nodeDID, nil).Return(&didDocument, nil, nil)
			mocks.Decrypter.EXPECT().Decrypt(ctx, keyDID.String(), gomock.Any()).Return(nil, errors.New("will return nil for PAL decryption")).Times(2)
			conns := grpc.NewStubConnectionList(authenticatedPeer)
			p.connectionList = conns

			err := p.handleTransactionPayloadQuery(ctx, conns.Conn, &Envelope{Message: &Envelope_TransactionPayloadQuery{&TransactionPayloadQuery{TransactionRef: tx.Ref().Slice()}}})

			assert.NoError(t, err)
			assertEmptyPayloadResponse(t, tx, conns.Conn.SentMsgs[0])
		})
		t.Run("decoding of the PAL header failed (nodeDID not set)", func(t *testing.T) {
			p, mocks := newTestProtocol(t, &did.DID{})
			mocks.State.EXPECT().GetTransaction(gomock.Any(), tx.Ref()).Return(tx, nil)
			conns := grpc.NewStubConnectionList(authenticatedPeer)
			p.connectionList = conns

			err := p.handleTransactionPayloadQuery(ctx, conns.Conn, &Envelope{Message: &Envelope_TransactionPayloadQuery{&TransactionPayloadQuery{TransactionRef: tx.Ref().Slice()}}})

			assert.NoError(t, err)
			assertEmptyPayloadResponse(t, tx, conns.Conn.SentMsgs[0])
		})
		t.Run("peer is not in PAL", func(t *testing.T) {
			p, mocks := newTestProtocol(t, nodeDID)
			mocks.State.EXPECT().GetTransaction(gomock.Any(), tx.Ref()).Return(tx, nil)
			mocks.DocResolver.EXPECT().Resolve(*nodeDID, nil).Return(&didDocument, nil, nil)
			mocks.Decrypter.EXPECT().Decrypt(ctx, keyDID.String(), gomock.Any()).Return([]byte(nodeDID.String()), nil)
			conns := grpc.NewStubConnectionList(authenticatedPeer)
			p.connectionList = conns

			err := p.handleTransactionPayloadQuery(ctx, conns.Conn, &Envelope{Message: &Envelope_TransactionPayloadQuery{&TransactionPayloadQuery{TransactionRef: tx.Ref().Slice()}}})

			assert.NoError(t, err)
			assertEmptyPayloadResponse(t, tx, conns.Conn.SentMsgs[0])
		})
		t.Run("ok", func(t *testing.T) {
			p, mocks := newTestProtocol(t, nodeDID)
			mocks.State.EXPECT().GetTransaction(gomock.Any(), tx.Ref()).Return(tx, nil)
			mocks.DocResolver.EXPECT().Resolve(*nodeDID, nil).Return(&didDocument, nil, nil)
			mocks.Decrypter.EXPECT().Decrypt(ctx, keyDID.String(), gomock.Any()).Return([]byte(peerDID.String()), nil)
			mocks.State.EXPECT().ReadPayload(ctx, tx.PayloadHash()).Return([]byte{}, nil)
			conns := grpc.NewStubConnectionList(authenticatedPeer)
			p.connectionList = conns

			err := p.handleTransactionPayloadQuery(ctx, conns.Conn, &Envelope{Message: &Envelope_TransactionPayloadQuery{&TransactionPayloadQuery{TransactionRef: tx.Ref().Slice()}}})

			assert.NoError(t, err)
			assertPayloadResponse(t, tx, []byte{}, conns.Conn.SentMsgs[0])
		})
	})
}

func TestProtocol_handleGossip(t *testing.T) {
	xorLocal, xorPeer := hash.EmptyHash(), hash.FromSlice([]byte("test"))
	clockLocal, clockPeer := uint32(2), uint32(3)
	bytes := make([][]byte, 1)
	bytes[0] = xorPeer.Slice()
	ctx := context.Background()

	envelope := &Envelope{Message: &Envelope_Gossip{&Gossip{XOR: xorPeer.Slice(), LC: clockPeer, Transactions: bytes}}}

	t.Run("ok - xors match", func(t *testing.T) {
		p, mocks := newTestProtocol(t, nil)
		mocks.State.EXPECT().XOR(uint32(dag.MaxLamportClock)).Return(xorPeer, clockPeer)

		err := p.handleGossip(ctx, connection, envelope)

		assert.NoError(t, err)
	})

	// results in TransactionListQuery

	t.Run("ok - new transaction ref makes xors equal", func(t *testing.T) {
		envelope := &Envelope{Message: &Envelope_Gossip{&Gossip{XOR: xorPeer.Slice(), LC: clockPeer, Transactions: [][]byte{xorPeer.Slice()}}}}

		p, mocks := newTestProtocol(t, nil)
		mocks.State.EXPECT().XOR(uint32(dag.MaxLamportClock)).Return(xorLocal, clockLocal)
		mocks.State.EXPECT().IsPresent(gomock.Any(), xorPeer).Return(false, nil)
		mocks.Gossip.EXPECT().GossipReceived(peer, xorPeer)
		mocks.Sender.EXPECT().sendTransactionListQuery(connection, []hash.SHA256Hash{xorPeer}).Return(nil)

		err := p.handleGossip(ctx, connection, envelope)

		assert.NoError(t, err)
	})

	t.Run("ok - new transaction ref, xors still unequal but peers is behind", func(t *testing.T) {
		p, mocks := newTestProtocol(t, nil)
		mocks.State.EXPECT().XOR(uint32(dag.MaxLamportClock)).Return(xorLocal, clockPeer+1)
		mocks.State.EXPECT().IsPresent(gomock.Any(), xorPeer).Return(false, nil)
		mocks.Gossip.EXPECT().GossipReceived(peer, xorPeer)
		mocks.Sender.EXPECT().sendTransactionListQuery(connection, []hash.SHA256Hash{xorPeer}).Return(nil)

		err := p.handleGossip(ctx, connection, envelope)

		assert.NoError(t, err)
	})

	// results in State

	t.Run("ok - xors don't match, peer is behind", func(t *testing.T) {
		p, mocks := newTestProtocol(t, nil)
		mocks.State.EXPECT().XOR(uint32(dag.MaxLamportClock)).Return(xorLocal, clockPeer+1)
		mocks.State.EXPECT().IsPresent(gomock.Any(), xorPeer).Return(true, nil)
		mocks.Gossip.EXPECT().GossipReceived(peer, xorPeer)
		mocks.Sender.EXPECT().sendState(connection, xorLocal, clockPeer+1)

		err := p.handleGossip(ctx, connection, envelope)

		assert.NoError(t, err)
	})

	t.Run("ok - new transaction ref, xors still unequal", func(t *testing.T) {
		xorLocal := hash.FromSlice([]byte("completely different"))
		p, mocks := newTestProtocol(t, nil)
		mocks.State.EXPECT().XOR(uint32(dag.MaxLamportClock)).Return(xorLocal, clockLocal)
		mocks.State.EXPECT().IsPresent(gomock.Any(), xorPeer).Return(false, nil)
		mocks.Gossip.EXPECT().GossipReceived(peer, xorPeer)
		mocks.Sender.EXPECT().sendState(connection, xorLocal, clockLocal).Return(nil)

		err := p.handleGossip(ctx, connection, envelope)

		assert.NoError(t, err)
	})

	t.Run("ok - no transaction refs, xors do not match", func(t *testing.T) {
		envelope := &Envelope{Message: &Envelope_Gossip{&Gossip{XOR: xorPeer.Slice(), LC: clockLocal}}}

		p, mocks := newTestProtocol(t, nil)
		mocks.State.EXPECT().XOR(uint32(dag.MaxLamportClock)).Return(xorLocal, clockLocal)
		mocks.Sender.EXPECT().sendState(connection, xorLocal, clockLocal).Return(nil)

		err := p.handleGossip(ctx, connection, envelope)

		assert.NoError(t, err)
	})

	t.Run("ok - no new transaction refs, xors do not match", func(t *testing.T) {
		envelope := &Envelope{Message: &Envelope_Gossip{&Gossip{XOR: xorPeer.Slice(), LC: clockLocal, Transactions: [][]byte{xorLocal.Slice()}}}}

		p, mocks := newTestProtocol(t, nil)
		mocks.State.EXPECT().XOR(uint32(dag.MaxLamportClock)).Return(xorLocal, clockLocal)
		mocks.State.EXPECT().IsPresent(gomock.Any(), xorLocal).Return(true, nil)
		mocks.Gossip.EXPECT().GossipReceived(peer, xorLocal)
		mocks.Sender.EXPECT().sendState(connection, xorLocal, clockLocal).Return(nil)

		err := p.handleGossip(ctx, connection, envelope)

		assert.NoError(t, err)
	})

	// errors

	t.Run("error - new transaction ref, sendTransactionList fails", func(t *testing.T) {
		envelope := &Envelope{Message: &Envelope_Gossip{&Gossip{XOR: xorPeer.Slice(), LC: clockLocal - 1, Transactions: [][]byte{xorPeer.Slice()}}}}

		p, mocks := newTestProtocol(t, nil)
		mocks.State.EXPECT().XOR(uint32(dag.MaxLamportClock)).Return(xorLocal, clockLocal)
		mocks.State.EXPECT().IsPresent(gomock.Any(), xorPeer).Return(false, nil)
		mocks.Gossip.EXPECT().GossipReceived(peer, xorPeer)

		mocks.Sender.EXPECT().sendTransactionListQuery(connection, []hash.SHA256Hash{xorPeer}).Return(errors.New("custom"))

		err := p.handleGossip(ctx, connection, envelope)

		assert.EqualError(t, err, "custom")
	})

	t.Run("error", func(t *testing.T) {
		p, mocks := newTestProtocol(t, nil)
		mocks.State.EXPECT().XOR(uint32(dag.MaxLamportClock)).Return(xorLocal, clockLocal)
		mocks.State.EXPECT().IsPresent(gomock.Any(), xorPeer).Return(false, errors.New("custom"))
		mocks.Gossip.EXPECT().GossipReceived(peer, xorPeer)

		err := p.handleGossip(ctx, connection, envelope)

		assert.EqualError(t, err, "failed to handle Gossip message: custom")
	})
}

func TestProtocol_handleTransactionListQuery(t *testing.T) {
	conversationID := newConversationID()
	dagT1, _, _ := dag.CreateTestTransaction(1)
	dagT2, _, _ := dag.CreateTestTransaction(2, dagT1)
	h1 := dagT1.Ref()
	h2 := dagT2.Ref()

	ctx := context.Background()

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

		mocks.Sender.EXPECT().sendTransactionList(connection, conversationID, expectedTransactions)

		err := p.handleTransactionListQuery(ctx, connection, &Envelope{
			Message: &Envelope_TransactionListQuery{&TransactionListQuery{
				ConversationID: conversationID.slice(),
				Refs:           [][]byte{h2.Slice(), h1.Slice()}, // reverse order to test sorting
			}},
		})

		assert.NoError(t, err)
	})

	t.Run("ok - tx not present", func(t *testing.T) {
		p, mocks := newTestProtocol(t, nil)
		mocks.State.EXPECT().GetTransaction(context.Background(), h1).Return(nil, dag.ErrTransactionNotFound)
		mocks.State.EXPECT().GetTransaction(context.Background(), h2).Return(nil, dag.ErrTransactionNotFound)

		mocks.Sender.EXPECT().sendTransactionList(connection, conversationID, gomock.Any())

		err := p.handleTransactionListQuery(ctx, connection, &Envelope{
			Message: &Envelope_TransactionListQuery{&TransactionListQuery{
				ConversationID: conversationID.slice(),
				Refs:           [][]byte{h1.Slice(), h2.Slice()},
			}},
		})

		assert.NoError(t, err)
	})

	t.Run("context cancelled", func(t *testing.T) {
		p, _ := newTestProtocol(t, nil)

		ctx, cancelFunc := context.WithCancel(ctx)
		cancelFunc()

		err := p.handleTransactionListQuery(ctx, connection, &Envelope{
			Message: &Envelope_TransactionListQuery{&TransactionListQuery{
				ConversationID: conversationID.slice(),
				Refs:           [][]byte{h1.Slice(), h2.Slice()},
			}},
		})

		assert.ErrorIs(t, err, context.Canceled)
	})

	t.Run("error - on State.GetTransaction", func(t *testing.T) {
		p, mocks := newTestProtocol(t, nil)
		mocks.State.EXPECT().GetTransaction(context.Background(), h1).Return(nil, errors.New("custom"))

		err := p.handleTransactionListQuery(ctx, connection, &Envelope{
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

		err := p.handleTransactionListQuery(ctx, connection, &Envelope{
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
		mocks.State.EXPECT().ReadPayload(context.Background(), dagT1.PayloadHash()).Return(nil, dag.ErrPayloadNotFound)

		err := p.handleTransactionListQuery(ctx, connection, &Envelope{
			Message: &Envelope_TransactionListQuery{&TransactionListQuery{
				ConversationID: conversationID.slice(),
				Refs:           [][]byte{h2.Slice(), h1.Slice()}, // reverse order to test sorting
			}},
		})

		assert.ErrorContains(t, err, "transaction is missing payload")
	})

	t.Run("ok - empty request", func(t *testing.T) {
		p, _ := newTestProtocol(t, nil)

		err := p.handleTransactionListQuery(ctx, connection, &Envelope{
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
	peer := transport.Peer{ID: "peer"}
	ctx := context.Background()

	t.Run("ok", func(t *testing.T) {
		p, mocks := newTestProtocol(t, nil)

		mocks.State.EXPECT().FindBetweenLC(gomock.Any(), lcStart, lcEnd).Return([]dag.Transaction{tx1, tx2}, nil)
		mocks.State.EXPECT().ReadPayload(gomock.Any(), tx1.PayloadHash()).Return(payload, nil)
		mocks.State.EXPECT().ReadPayload(gomock.Any(), tx2.PayloadHash()).Return(payload, nil)
		mocks.Sender.EXPECT().sendTransactionList(connection, gomock.Any(), gomock.Any())

		msg := &Envelope_TransactionRangeQuery{&TransactionRangeQuery{
			Start: lcStart,
			End:   lcEnd,
		}}
		p.cMan.startConversation(msg, peer)
		err := p.handleTransactionRangeQuery(ctx, connection, &Envelope{Message: msg})

		assert.NoError(t, err)
	})
	t.Run("context cancelled", func(t *testing.T) {
		p, mocks := newTestProtocol(t, nil)

		mocks.State.EXPECT().FindBetweenLC(gomock.Any(), lcStart, lcEnd).Return([]dag.Transaction{tx1, tx2}, nil)

		msg := &Envelope_TransactionRangeQuery{&TransactionRangeQuery{
			Start: lcStart,
			End:   lcEnd,
		}}
		p.cMan.startConversation(msg, peer)

		ctx, cancelFunc := context.WithCancel(ctx)
		cancelFunc()
		err := p.handleTransactionRangeQuery(ctx, connection, &Envelope{Message: msg})

		assert.ErrorIs(t, err, context.Canceled)
	})
	t.Run("error - invalid range", func(t *testing.T) {
		p, _ := newTestProtocol(t, nil)

		msg := &Envelope_TransactionRangeQuery{&TransactionRangeQuery{
			Start: 1,
			End:   1,
		}}
		p.cMan.startConversation(msg, peer)
		err := p.handleTransactionRangeQuery(ctx, connection, &Envelope{Message: msg})

		assert.EqualError(t, err, "invalid range query")
	})
	t.Run("error - DAG reading error", func(t *testing.T) {
		p, mocks := newTestProtocol(t, nil)
		mocks.State.EXPECT().FindBetweenLC(gomock.Any(), lcStart, lcEnd).Return(nil, errors.New("failure"))
		msg := &Envelope_TransactionRangeQuery{&TransactionRangeQuery{
			Start: lcStart,
			End:   lcEnd,
		}}
		p.cMan.startConversation(msg, peer)
		err := p.handleTransactionRangeQuery(ctx, connection, &Envelope{Message: msg})

		assert.Error(t, err)
	})
}

func TestProtocol_handleState(t *testing.T) {
	peerXor, localXor := hash.FromSlice([]byte("peer")), hash.FromSlice([]byte("local"))
	peerClock, localClock := uint32(6), uint32(5)
	t.Run("ok - xors are the same", func(t *testing.T) {
		msg := &Envelope_State{State: &State{LC: peerClock, XOR: peerXor.Slice()}}
		p, mocks := newTestProtocol(t, nil)
		mocks.State.EXPECT().XOR(uint32(dag.MaxLamportClock)).Return(peerXor, localClock)

		err := p.handleState(context.Background(), connection, &Envelope{Message: msg})

		assert.NoError(t, err)
	})

	t.Run("ok - TransactionSet response", func(t *testing.T) {
		msg := &Envelope_State{State: &State{LC: peerClock, XOR: peerXor.Slice()}}
		iblt := *tree.NewIblt(10)
		p, mocks := newTestProtocol(t, nil)
		conversation := p.cMan.startConversation(msg, testPeer)
		mocks.State.EXPECT().XOR(uint32(dag.MaxLamportClock)).Return(localXor, localClock)
		mocks.State.EXPECT().IBLT(peerClock).Return(iblt, uint32(0))
		mocks.Sender.EXPECT().sendTransactionSet(connection, conversation.conversationID, peerClock, localClock, iblt)

		err := p.handleState(context.Background(), connection, &Envelope{Message: msg})

		assert.NoError(t, err)
	})
}

func TestProtocol_handleTransactionSet(t *testing.T) {
	requestLC := uint32(3)
	request := &Envelope_State{State: &State{LC: requestLC, XOR: hash.FromSlice([]byte("requestXOR")).Slice()}}
	peer := transport.Peer{ID: "peerID"}

	emptyIblt := tree.NewIblt(10)
	emptyIbltBytes, _ := emptyIblt.MarshalBinary()

	hash1, _, _ := dag.CreateTestTransaction(1)
	oneHashIblt := emptyIblt.Clone().(*tree.Iblt)
	oneHashIblt.Insert(hash1.Ref())
	oneHashIbltBytes, _ := oneHashIblt.MarshalBinary()

	ctx := context.Background()

	t.Run("ok - decode success, peer is behind", func(t *testing.T) {
		peerLC := requestLC - 1
		localLC := requestLC
		p, mocks := newTestProtocol(t, nil)
		conversation := p.cMan.startConversation(request, peer)
		mocks.State.EXPECT().IBLT(peerLC).Return(*oneHashIblt.Clone().(*tree.Iblt), dag.PageSize-1)
		mocks.State.EXPECT().XOR(uint32(dag.MaxLamportClock)).Return(hash.FromSlice([]byte("ignored")), localLC)

		err := p.handleTransactionSet(ctx, connection, &Envelope{Message: &Envelope_TransactionSet{
			TransactionSet: &TransactionSet{ConversationID: conversation.conversationID.slice(), LCReq: requestLC, LC: peerLC, IBLT: emptyIbltBytes},
		}})

		assert.NoError(t, err)
		assert.Nil(t, p.cMan.conversations[conversation.conversationID.String()]) // conversation marked done
	})

	t.Run("ok - decode success, request new Tx", func(t *testing.T) {
		peerLC := requestLC - 1
		p, mocks := newTestProtocol(t, nil)
		conversation := p.cMan.startConversation(request, peer)
		mocks.State.EXPECT().IBLT(peerLC).Return(*emptyIblt.Clone().(*tree.Iblt), dag.PageSize-1)
		mocks.Sender.EXPECT().sendTransactionListQuery(connection, []hash.SHA256Hash{hash1.Ref()}).Return(nil)

		err := p.handleTransactionSet(ctx, connection, &Envelope{Message: &Envelope_TransactionSet{
			TransactionSet: &TransactionSet{ConversationID: conversation.conversationID.slice(), LCReq: requestLC, LC: peerLC, IBLT: oneHashIbltBytes},
		}})

		assert.NoError(t, err)
		assert.Nil(t, p.cMan.conversations[conversation.conversationID.String()]) // conversation marked done
	})

	t.Run("ok - decode success comparing historic pages, no new Tx -> request next page", func(t *testing.T) {
		localLC := requestLC + dag.PageSize
		peerLC := requestLC + dag.PageSize*3
		p, mocks := newTestProtocol(t, nil)
		conversation := p.cMan.startConversation(request, peer)
		mocks.State.EXPECT().IBLT(requestLC).Return(*oneHashIblt.Clone().(*tree.Iblt), dag.PageSize-1)
		mocks.State.EXPECT().XOR(uint32(dag.MaxLamportClock)).Return(hash.FromSlice([]byte("ignored")), localLC)
		mocks.Sender.EXPECT().sendTransactionRangeQuery(connection, dag.PageSize, 2*dag.PageSize).Return(nil)

		err := p.handleTransactionSet(ctx, connection, &Envelope{Message: &Envelope_TransactionSet{
			TransactionSet: &TransactionSet{ConversationID: conversation.conversationID.slice(), LCReq: requestLC, LC: peerLC, IBLT: oneHashIbltBytes},
		}})

		assert.NoError(t, err)
		assert.Nil(t, p.cMan.conversations[conversation.conversationID.String()]) // conversation marked done
	})

	t.Run("ok - decode success, no new Tx -> request DAG sync", func(t *testing.T) {
		peerLC := requestLC + dag.PageSize
		p, mocks := newTestProtocol(t, nil)
		conversation := p.cMan.startConversation(request, peer)
		mocks.State.EXPECT().IBLT(requestLC).Return(*oneHashIblt.Clone().(*tree.Iblt), dag.PageSize-1)
		mocks.State.EXPECT().XOR(uint32(dag.MaxLamportClock)).Return(hash.FromSlice([]byte("ignored")), requestLC)
		mocks.Sender.EXPECT().sendTransactionRangeQuery(connection, dag.PageSize, uint32(dag.MaxLamportClock)).Return(nil)

		err := p.handleTransactionSet(ctx, connection, &Envelope{Message: &Envelope_TransactionSet{
			TransactionSet: &TransactionSet{ConversationID: conversation.conversationID.slice(), LCReq: requestLC, LC: peerLC, IBLT: oneHashIbltBytes},
		}})

		assert.NoError(t, err)
		assert.Nil(t, p.cMan.conversations[conversation.conversationID.String()]) // conversation marked done
	})

	t.Run("ok - decode fails, new state msg", func(t *testing.T) {
		localXor := hash.FromSlice([]byte("localXOR"))
		page1RequestLC := dag.PageSize + requestLC
		request := &Envelope_State{State: &State{LC: page1RequestLC, XOR: hash.FromSlice([]byte("requestXOR")).Slice()}}
		conflictingIblt := emptyIblt.Clone().(*tree.Iblt)
		conflictingIblt.Insert(hash1.Ref())
		conflictingIblt.Insert(hash1.Ref())
		p, mocks := newTestProtocol(t, nil)
		conversation := p.cMan.startConversation(request, peer)
		mocks.State.EXPECT().IBLT(page1RequestLC).Return(*conflictingIblt, dag.PageSize-1)
		mocks.State.EXPECT().XOR(uint32(dag.MaxLamportClock)).Return(localXor, uint32(0))
		mocks.Sender.EXPECT().sendState(connection, localXor, dag.PageSize-1).Return(nil)

		err := p.handleTransactionSet(ctx, connection, &Envelope{Message: &Envelope_TransactionSet{
			TransactionSet: &TransactionSet{ConversationID: conversation.conversationID.slice(), LCReq: page1RequestLC, LC: page1RequestLC, IBLT: emptyIbltBytes},
		}})

		assert.NoError(t, err)
		assert.Nil(t, p.cMan.conversations[conversation.conversationID.String()]) // conversation marked done
	})

	t.Run("ok - decode fails, request first page", func(t *testing.T) {
		conflictingIblt := emptyIblt.Clone().(*tree.Iblt)
		conflictingIblt.Insert(hash1.Ref())
		conflictingIblt.Insert(hash1.Ref())
		p, mocks := newTestProtocol(t, nil)
		conversation := p.cMan.startConversation(request, peer)
		mocks.State.EXPECT().IBLT(requestLC).Return(*conflictingIblt, dag.PageSize-1)
		mocks.Sender.EXPECT().sendTransactionRangeQuery(connection, uint32(0), dag.PageSize).Return(nil)

		err := p.handleTransactionSet(ctx, connection, &Envelope{Message: &Envelope_TransactionSet{
			TransactionSet: &TransactionSet{ConversationID: conversation.conversationID.slice(), LCReq: requestLC, LC: requestLC, IBLT: emptyIbltBytes},
		}})

		assert.NoError(t, err)
		assert.Nil(t, p.cMan.conversations[conversation.conversationID.String()]) // conversation marked done
	})

	t.Run("error - unknown conversationID", func(t *testing.T) {
		p, _ := newTestProtocol(t, nil)
		conversationID := newConversationID()

		err := p.handleTransactionSet(ctx, connection, &Envelope{Message: &Envelope_TransactionSet{
			TransactionSet: &TransactionSet{
				ConversationID: conversationID.slice(),
			},
		}})

		assert.EqualError(t, err, fmt.Sprintf("unknown or expired conversation (id=%s)", conversationID.String()))
	})

	t.Run("error - iblt subtract fails", func(t *testing.T) {
		p, mocks := newTestProtocol(t, nil)
		conversation := p.cMan.startConversation(request, peer)
		mocks.State.EXPECT().IBLT(requestLC).Return(*tree.NewIblt(20), dag.PageSize-1)

		emptyIbltBytes, _ := emptyIblt.MarshalBinary()

		response := &Envelope{Message: &Envelope_TransactionSet{
			TransactionSet: &TransactionSet{ConversationID: conversation.conversationID.slice(), LCReq: requestLC, LC: requestLC, IBLT: emptyIbltBytes},
		}}

		err := p.handleTransactionSet(ctx, connection, response)

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
