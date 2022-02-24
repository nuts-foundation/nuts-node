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

		mocks.State.EXPECT().GetTransaction(gomock.Any(), tx.Ref()).Return(tx, nil)
		mocks.State.EXPECT().WritePayload(gomock.Any(), tx.PayloadHash(), payload)
		mocks.PayloadScheduler.EXPECT().Finished(tx.Ref()).Return(nil)

		err := p.Handle(peer, &Envelope{Message: &Envelope_TransactionPayload{&TransactionPayload{TransactionRef: tx.Ref().Slice(), Data: payload}}})

		assert.NoError(t, err)
	})

	t.Run("error - no tx ref", func(t *testing.T) {
		p, _ := newTestProtocol(t, nil)
		envelope := &Envelope{Message: &Envelope_TransactionPayload{&TransactionPayload{}}}
		err := p.Handle(peer, envelope)

		assert.EqualError(t, err, "msg is missing transaction reference")
	})

	t.Run("error - no data", func(t *testing.T) {
		p, _ := newTestProtocol(t, nil)
		err := p.Handle(peer, &Envelope{Message: &Envelope_TransactionPayload{&TransactionPayload{TransactionRef: []byte{1, 2, 3}}}})

		assert.EqualError(t, err, "peer does not have transaction payload (tx=0102030000000000000000000000000000000000000000000000000000000000)")
	})

	t.Run("error - payload does not match hash", func(t *testing.T) {
		p, mocks := newTestProtocol(t, nil)
		mocks.State.EXPECT().GetTransaction(gomock.Any(), tx.Ref()).Return(tx, nil)

		err := p.Handle(peer, &Envelope{Message: &Envelope_TransactionPayload{&TransactionPayload{TransactionRef: tx.Ref().Slice(), Data: []byte("Hello, victim!")}}})

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "peer sent payload that doesn't match payload hash")
	})

	t.Run("error - tx not present", func(t *testing.T) {
		p, mocks := newTestProtocol(t, nil)
		mocks.State.EXPECT().GetTransaction(gomock.Any(), tx.Ref()).Return(nil, nil)

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
			mocks.State.EXPECT().GetTransaction(gomock.Any(), tx.Ref()).Return(tx, nil)
			mocks.State.EXPECT().ReadPayload(gomock.Any(), gomock.Any()).Return(payload, nil)

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
			mocks.State.EXPECT().GetTransaction(gomock.Any(), tx.Ref()).Return(nil, nil)

			conns := &grpc.StubConnectionList{
				Conn: &grpc.StubConnection{PeerID: peer.ID},
			}
			p.connectionList = conns

			err := p.Handle(peer, &Envelope{Message: &Envelope_TransactionPayloadQuery{&TransactionPayloadQuery{TransactionRef: tx.Ref().Slice()}}})

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

			err := p.Handle(peer, &Envelope{Message: &Envelope_TransactionPayloadQuery{&TransactionPayloadQuery{TransactionRef: tx.Ref().Slice()}}})

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

			err := p.Handle(authenticatedPeer, &Envelope{Message: &Envelope_TransactionPayloadQuery{&TransactionPayloadQuery{TransactionRef: tx.Ref().Slice()}}})

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

			err := p.Handle(authenticatedPeer, &Envelope{Message: &Envelope_TransactionPayloadQuery{&TransactionPayloadQuery{TransactionRef: tx.Ref().Slice()}}})

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

			err := p.Handle(authenticatedPeer, &Envelope{Message: &Envelope_TransactionPayloadQuery{&TransactionPayloadQuery{TransactionRef: tx.Ref().Slice()}}})

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

			err := p.Handle(authenticatedPeer, &Envelope{Message: &Envelope_TransactionPayloadQuery{&TransactionPayloadQuery{TransactionRef: tx.Ref().Slice()}}})

			assert.NoError(t, err)
			assertPayloadResponse(t, tx, []byte{}, conns.Conn.SentMsgs[0])
		})
	})
}

func TestProtocol_handleGossip(t *testing.T) {
	bytes := make([][]byte, 1)
	bytes[0] = hash.EmptyHash().Slice()

	t.Run("ok - new transaction ref", func(t *testing.T) {
		p, mocks := newTestProtocol(t, nil)
		mocks.State.EXPECT().IsPresent(gomock.Any(), hash.EmptyHash()).Return(false, nil)
		mocks.Gossip.EXPECT().GossipReceived(peer.ID, hash.EmptyHash())

		err := p.Handle(peer, &Envelope{
			Message: &Envelope_Gossip{&Gossip{Transactions: bytes}},
		})

		assert.NoError(t, err)
	})

	t.Run("ok - existing transaction ref", func(t *testing.T) {
		p, mocks := newTestProtocol(t, nil)
		mocks.State.EXPECT().IsPresent(gomock.Any(), hash.EmptyHash()).Return(true, nil)
		mocks.Gossip.EXPECT().GossipReceived(peer.ID, []hash.SHA256Hash{})

		err := p.Handle(peer, &Envelope{
			Message: &Envelope_Gossip{&Gossip{Transactions: bytes}},
		})

		assert.NoError(t, err)
	})

	t.Run("error", func(t *testing.T) {
		p, mocks := newTestProtocol(t, nil)
		mocks.State.EXPECT().IsPresent(gomock.Any(), hash.EmptyHash()).Return(false, errors.New("custom"))

		err := p.Handle(peer, &Envelope{
			Message: &Envelope_Gossip{&Gossip{Transactions: bytes}},
		})

		assert.EqualError(t, err, "failed to handle Gossip message: custom")
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
