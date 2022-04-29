/*
 * Nuts node
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
	"errors"
	"github.com/google/uuid"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"google.golang.org/protobuf/proto"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-node/network/dag/tree"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/nuts-foundation/nuts-node/network/transport/grpc"
	"github.com/stretchr/testify/assert"
)

func TestProtocol_sendGossip(t *testing.T) {
	peerID := transport.PeerID("1")
	xor := hash.EmptyHash()
	clock := uint32(5)
	refsAsBytes := [][]byte{xor.Slice()}
	envelope := &Envelope{Message: &Envelope_Gossip{
		Gossip: &Gossip{
			XOR:          xor.Slice(),
			LC:           clock,
			Transactions: refsAsBytes,
		},
	}}

	t.Run("ok", func(t *testing.T) {
		proto, mocks := newTestProtocol(t, nil)
		mockConnection := grpc.NewMockConnection(mocks.Controller)
		mocks.ConnectionList.EXPECT().Get(grpc.ByConnected(), grpc.ByPeerID(peerID)).Return(mockConnection)
		mockConnection.EXPECT().Send(proto, envelope)

		err := proto.sendGossipMsg(peerID, []hash.SHA256Hash{hash.EmptyHash()}, xor, clock)

		assert.NoError(t, err)
	})

	performSendErrorTest(t, peerID, gomock.Eq(envelope), func(p *protocol, mocks protocolMocks) error {
		return p.sendGossipMsg(peerID, []hash.SHA256Hash{hash.EmptyHash()}, xor, clock)
	})
	performNoConnectionAvailableTest(t, peerID, func(p *protocol, _ protocolMocks) error {
		return p.sendGossipMsg(peerID, []hash.SHA256Hash{hash.EmptyHash()}, xor, clock)
	})
}

func TestProtocol_sendTransactionList(t *testing.T) {
	peer := transport.Peer{ID: "1"}
	conversationID := newConversationID()
	largeTransaction := Transaction{
		Data: make([]byte, grpc.MaxMessageSizeInBytes/2),
	}
	networkTXs := []*Transaction{&largeTransaction}
	envelope := &Envelope{Message: &Envelope_TransactionList{
		TransactionList: &TransactionList{
			ConversationID: conversationID.slice(),
			Transactions:   networkTXs,
			MessageNumber:  1,
			TotalMessages:  1,
		},
	}}

	t.Run("ok", func(t *testing.T) {
		proto, mocks := newTestProtocol(t, nil)
		mockConnection := grpc.NewMockConnection(mocks.Controller)
		mocks.ConnectionList.EXPECT().Get(grpc.ByConnected(), grpc.ByPeerID(peer.ID)).Return(mockConnection)
		mockConnection.EXPECT().Send(proto, envelope)

		err := proto.sendTransactionList(peer.ID, conversationID, networkTXs)

		assert.NoError(t, err)
	})

	t.Run("ok - 2 messages", func(t *testing.T) {
		proto, mocks := newTestProtocol(t, nil)
		mockConnection := grpc.NewMockConnection(mocks.Controller)
		mocks.ConnectionList.EXPECT().Get(grpc.ByConnected(), grpc.ByPeerID(peer.ID)).Return(mockConnection)
		mockConnection.EXPECT().Send(proto, &Envelope{Message: &Envelope_TransactionList{
			TransactionList: &TransactionList{
				ConversationID: conversationID.slice(),
				Transactions:   []*Transaction{&largeTransaction},
				MessageNumber:  1,
				TotalMessages:  2,
			},
		}})
		mockConnection.EXPECT().Send(proto, &Envelope{Message: &Envelope_TransactionList{
			TransactionList: &TransactionList{
				ConversationID: conversationID.slice(),
				Transactions:   []*Transaction{&largeTransaction},
				MessageNumber:  2,
				TotalMessages:  2,
			},
		}})

		err := proto.sendTransactionList(peer.ID, conversationID, []*Transaction{&largeTransaction, &largeTransaction})

		assert.NoError(t, err)
	})

	performSendErrorTest(t, peer.ID, gomock.Eq(envelope), func(p *protocol, _ protocolMocks) error {
		return p.sendTransactionList(peer.ID, conversationID, networkTXs)
	})
	performNoConnectionAvailableTest(t, peer.ID, func(p *protocol, _ protocolMocks) error {
		return p.sendTransactionList(peer.ID, newConversationID(), []*Transaction{})
	})
}

func TestProtocol_sendTransactionRangeQuery(t *testing.T) {
	peerID := transport.PeerID("1")

	t.Run("ok", func(t *testing.T) {
		proto, mocks := newTestProtocol(t, nil)
		mockConnection := grpc.NewMockConnection(mocks.Controller)
		mocks.ConnectionList.EXPECT().Get(grpc.ByConnected(), grpc.ByPeerID(peerID)).Return(mockConnection)
		var actualEnvelope *Envelope
		mockConnection.EXPECT().Send(proto, gomock.Any()).DoAndReturn(func(p *protocol, e *Envelope) error {
			actualEnvelope = e
			return nil
		})

		err := proto.sendTransactionRangeQuery(peerID, 1, 5)

		assert.NoError(t, err)
		assert.Len(t, proto.cMan.conversations, 1) // assert a conversation was started
		assert.NotNil(t, actualEnvelope.GetTransactionRangeQuery().GetConversationID())
	})

	performSendErrorTest(t, peerID, gomock.Any(), func(p *protocol, _ protocolMocks) error {
		return p.sendTransactionRangeQuery(peerID, 1, 5)
	})
	performNoConnectionAvailableTest(t, peerID, func(p *protocol, _ protocolMocks) error {
		return p.sendTransactionRangeQuery(peerID, 1, 5)
	})
}

func Test_chunkTransactionList(t *testing.T) {
	t.Run("calculate overhead", func(t *testing.T) {
		const numTX = 100
		var txs []*Transaction
		dataLen := 0
		for i := 0; i < numTX; i++ {
			tx, _, _ := dag.CreateTestTransaction(1)
			payload := []byte{1, 2, 3, 4, 5, 6}
			txs = append(txs, &Transaction{Data: tx.Data(), Payload: payload})
			dataLen += len(tx.Data()) + len(payload)
		}

		sizeEmpty := proto.Size(&Envelope{Message: &Envelope_TransactionList{
			TransactionList: &TransactionList{
				ConversationID: []byte(uuid.New().String()),
			},
		}})
		println("Message size for empty TransactionList (message overhead):", sizeEmpty)

		sizeNonEmpty := proto.Size(&Envelope{Message: &Envelope_TransactionList{
			TransactionList: &TransactionList{
				ConversationID: []byte(uuid.New().String()),
				Transactions:   txs,
			},
		}})
		println("Message size for", numTX, "transactions:", sizeNonEmpty)
		println("Length of data (TX data + payload is):", dataLen)
		println("Delta:", sizeNonEmpty-dataLen)
		overheadPerTX := (sizeNonEmpty - sizeEmpty - dataLen) / numTX
		println("Overhead per TX:", overheadPerTX)

		assert.True(t, transactionListMessageOverhead >= sizeEmpty)
		assert.True(t, transactionListTXOverhead >= overheadPerTX)
	})
	t.Run("no chunks", func(t *testing.T) {
		transactions := []*Transaction{{}, {}}

		chunks := chunkTransactionList(transactions)

		if !assert.Len(t, chunks, 1) {
			return
		}
		assert.Len(t, chunks[0], 2)
	})

	t.Run("2 large chunks", func(t *testing.T) {
		largeTransaction := Transaction{
			Data: make([]byte, grpc.MaxMessageSizeInBytes/2),
		}
		transactions := []*Transaction{&largeTransaction, &largeTransaction}

		chunks := chunkTransactionList(transactions)

		if !assert.Len(t, chunks, 2) {
			return
		}
		assert.Len(t, chunks[0], 1)
		assert.Len(t, chunks[1], 1)
	})

	t.Run("complex set", func(t *testing.T) {
		transactions := []*Transaction{
			{Data: make([]byte, 100000)},
			{Data: make([]byte, 256000)},
			{Data: make([]byte, 100000)},
			{Data: make([]byte, 256000)}, // doesn't fit
			{Data: make([]byte, 15000)},
			{Data: make([]byte, 256000)}, // doesn't fit
		}

		chunks := chunkTransactionList(transactions)

		assert.Len(t, chunks, 3)
	})
}

func TestProtocol_sendState(t *testing.T) {
	peerID := transport.PeerID("1")
	xor := hash.EmptyHash()
	clock := uint32(5)

	t.Run("ok", func(t *testing.T) {
		proto, mocks := newTestProtocol(t, nil)
		var actualEnvelope *Envelope

		mockConnection := grpc.NewMockConnection(mocks.Controller)
		mocks.ConnectionList.EXPECT().Get(grpc.ByConnected(), grpc.ByPeerID(peerID)).Return(mockConnection)
		mockConnection.EXPECT().Send(proto, gomock.Any()).DoAndReturn(func(p *protocol, e *Envelope) error {
			actualEnvelope = e
			return nil
		})

		err := proto.sendState(peerID, xor, clock)

		if !assert.NoError(t, err) {
			return
		}
		assert.Len(t, proto.cMan.conversations, 1) // assert a conversation was started
		assert.NotNil(t, actualEnvelope.GetState().GetConversationID())
		assert.Equal(t, xor.Slice(), actualEnvelope.GetState().XOR)
		assert.Equal(t, clock, actualEnvelope.GetState().LC)
	})

	performSendErrorTest(t, peerID, gomock.Any(), func(p *protocol, mocks protocolMocks) error {
		return p.sendState(peerID, xor, clock)
	})
	performNoConnectionAvailableTest(t, peerID, func(p *protocol, _ protocolMocks) error {
		return p.sendState(peerID, xor, clock)
	})
}

func TestProtocol_sendTransactionSet(t *testing.T) {
	peerID := transport.PeerID("1")
	conversationID := newConversationID()
	clock := uint32(5)
	clockReq := uint32(4)
	iblt := tree.NewIblt(1)
	ibltBytes, _ := iblt.MarshalBinary()
	envelope := &Envelope{Message: &Envelope_TransactionSet{TransactionSet: &TransactionSet{
		ConversationID: conversationID.slice(),
		LCReq:          clockReq,
		LC:             clock,
		IBLT:           ibltBytes,
	}}}

	t.Run("ok", func(t *testing.T) {
		proto, mocks := newTestProtocol(t, nil)
		mockConnection := grpc.NewMockConnection(mocks.Controller)
		mocks.ConnectionList.EXPECT().Get(grpc.ByConnected(), grpc.ByPeerID(peer.ID)).Return(mockConnection)
		mockConnection.EXPECT().Send(proto, envelope)

		err := proto.sendTransactionSet(peer.ID, conversationID, clockReq, clock, *iblt)

		assert.NoError(t, err)
	})

	performSendErrorTest(t, peerID, gomock.Any(), func(p *protocol, mocks protocolMocks) error {
		return p.sendTransactionSet(peerID, conversationID, clockReq, clock, *iblt)
	})
	performNoConnectionAvailableTest(t, peerID, func(p *protocol, _ protocolMocks) error {
		return p.sendTransactionSet(peerID, conversationID, clockReq, clock, *iblt)
	})
}

func TestProtocol_broadcastDiagnostics(t *testing.T) {
	envelope := &Envelope{Message: &Envelope_DiagnosticsBroadcast{
		DiagnosticsBroadcast: &Diagnostics{
			Uptime:               1,
			PeerID:               "",
			Peers:                []string{"1","2"},
			NumberOfTransactions: 100,
			SoftwareVersion:      "abc",
			SoftwareID:           "def",
		},
	}}

	proto, mocks := newTestProtocol(t, nil)
	conn1 := grpc.NewMockConnection(mocks.Controller)
	conn1.EXPECT().Send(proto, envelope)
	// Second connection returns an error, which is just logged
	conn2 := grpc.NewMockConnection(mocks.Controller)
	conn2.EXPECT().Send(proto, envelope).Return(errors.New("error"))
	conn2.EXPECT().Peer().Return(transport.Peer{})
	mocks.ConnectionList.EXPECT().AllMatching(grpc.ByConnected()).Return([]grpc.Connection{conn1, conn2})

	proto.broadcastDiagnostics(transport.Diagnostics{
		Uptime:               time.Second,
		Peers:                []transport.PeerID{"1", "2"},
		NumberOfTransactions: 100,
		SoftwareVersion:      "abc",
		SoftwareID:           "def",
	})
}

func performSendErrorTest(t *testing.T, peerID transport.PeerID, envelope gomock.Matcher, sender func(*protocol, protocolMocks) error) {
	t.Run("error - error on send", func(t *testing.T) {
		proto, mocks := newTestProtocol(t, nil)
		mockConnection := grpc.NewMockConnection(mocks.Controller)
		mocks.ConnectionList.EXPECT().Get(grpc.ByConnected(), grpc.ByPeerID(peerID)).Return(mockConnection)
		mockConnection.EXPECT().Send(proto, envelope).Return(errors.New("custom"))

		err := sender(proto, mocks)

		assert.Error(t, err)
	})
}

func performNoConnectionAvailableTest(t *testing.T, peerID transport.PeerID, sender func(*protocol, protocolMocks) error) {
	t.Run("error - no connection available", func(t *testing.T) {
		proto, mocks := newTestProtocol(t, nil)
		mocks.ConnectionList.EXPECT().Get(grpc.ByConnected(), grpc.ByPeerID(peerID)).Return(nil)

		err := sender(proto, mocks)

		assert.Error(t, err)
	})
}
