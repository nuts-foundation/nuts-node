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
	"testing"

	"github.com/golang/mock/gomock"
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
		mocks.State.EXPECT().XOR(gomock.Any(), gomock.Any()).Return(xor, clock)
		mockConnection.EXPECT().Send(proto, envelope)

		err := proto.sendGossipMsg(peerID, []hash.SHA256Hash{hash.EmptyHash()})

		assert.NoError(t, err)
	})

	performSendErrorTest(t, peerID, gomock.Eq(envelope), func(p *protocol, mocks protocolMocks) error {
		mocks.State.EXPECT().XOR(gomock.Any(), gomock.Any()).Return(xor, clock)
		return p.sendGossipMsg(peerID, []hash.SHA256Hash{hash.EmptyHash()})
	})
	performNoConnectionAvailableTest(t, peerID, func(p *protocol, _ protocolMocks) error {
		return p.sendGossipMsg(peerID, []hash.SHA256Hash{hash.EmptyHash()})
	})
}

func TestProtocol_sendTransactionList(t *testing.T) {
	peerID := transport.PeerID("1")
	conversationID := newConversationID()
	largeTransaction := Transaction{
		Data: make([]byte, grpc.MaxMessageSizeInBytes/2),
	}
	transactions := []*Transaction{&largeTransaction, &largeTransaction}
	envelope := &Envelope{Message: &Envelope_TransactionList{
		TransactionList: &TransactionList{
			ConversationID: conversationID.slice(),
			Transactions:   []*Transaction{&largeTransaction},
		},
	}}

	t.Run("ok", func(t *testing.T) {
		proto, mocks := newTestProtocol(t, nil)
		mockConnection := grpc.NewMockConnection(mocks.Controller)
		mocks.ConnectionList.EXPECT().Get(grpc.ByConnected(), grpc.ByPeerID(peerID)).Return(mockConnection)
		mockConnection.EXPECT().Send(proto, envelope).Times(2)

		err := proto.sendTransactionList(peerID, conversationID, transactions)

		assert.NoError(t, err)
	})

	performSendErrorTest(t, peerID, gomock.Eq(envelope), func(p *protocol, _ protocolMocks) error {
		return p.sendTransactionList(peerID, conversationID, transactions)
	})
	performNoConnectionAvailableTest(t, peerID, func(p *protocol, _ protocolMocks) error {
		return p.sendTransactionList(peerID, newConversationID(), []*Transaction{})
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
