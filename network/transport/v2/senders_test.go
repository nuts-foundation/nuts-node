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

	t.Run("ok", func(t *testing.T) {
		proto, mocks := newTestProtocol(t, nil)
		mockConnection := grpc.NewMockConnection(mocks.Controller)
		mocks.ConnectionList.EXPECT().Get(grpc.ByConnected(), grpc.ByPeerID(peerID)).Return(mockConnection)
		mocks.State.EXPECT().XOR(gomock.Any(), gomock.Any()).Return(xor, clock)
		mockConnection.EXPECT().Send(proto, &Envelope{Message: &Envelope_Gossip{
			Gossip: &Gossip{
				XOR:          xor.Slice(),
				LC:           clock,
				Transactions: refsAsBytes,
			},
		}})

		success := proto.sendGossip(peerID, []hash.SHA256Hash{hash.EmptyHash()})

		assert.True(t, success)
	})
	t.Run("error - no connection available", func(t *testing.T) {
		proto, mocks := newTestProtocol(t, nil)
		mocks.ConnectionList.EXPECT().Get(grpc.ByConnected(), grpc.ByPeerID(peerID)).Return(nil)

		success := proto.sendGossip(peerID, []hash.SHA256Hash{hash.EmptyHash()})

		assert.False(t, success)
	})
}

func TestProtocol_sendTransactionList(t *testing.T) {
	peerID := transport.PeerID("1")
	conversationID := newConversationID()
	largeTransaction := Transaction{
		Data: make([]byte, grpc.MaxMessageSizeInBytes/2),
	}
	transactions := []*Transaction{&largeTransaction, &largeTransaction}

	t.Run("ok", func(t *testing.T) {
		proto, mocks := newTestProtocol(t, nil)
		mockConnection := grpc.NewMockConnection(mocks.Controller)
		mocks.ConnectionList.EXPECT().Get(grpc.ByConnected(), grpc.ByPeerID(peerID)).Return(mockConnection)
		mockConnection.EXPECT().Send(proto, &Envelope{Message: &Envelope_TransactionList{
			TransactionList: &TransactionList{
				ConversationID: conversationID.slice(),
				Transactions:   []*Transaction{&largeTransaction},
			},
		}}).Times(2)

		err := proto.sendTransactionList(peerID, conversationID, transactions)

		assert.NoError(t, err)
	})
	t.Run("error - on send", func(t *testing.T) {
		proto, mocks := newTestProtocol(t, nil)
		mockConnection := grpc.NewMockConnection(mocks.Controller)
		mocks.ConnectionList.EXPECT().Get(grpc.ByConnected(), grpc.ByPeerID(peerID)).Return(mockConnection)
		mockConnection.EXPECT().Send(proto, &Envelope{Message: &Envelope_TransactionList{
			TransactionList: &TransactionList{
				ConversationID: conversationID.slice(),
				Transactions:   []*Transaction{&largeTransaction},
			},
		}}).Return(errors.New("custom"))

		err := proto.sendTransactionList(peerID, conversationID, transactions)

		assert.Error(t, err)
	})
	t.Run("error - no connection available", func(t *testing.T) {
		proto, mocks := newTestProtocol(t, nil)
		mocks.ConnectionList.EXPECT().Get(grpc.ByConnected(), grpc.ByPeerID(peerID)).Return(nil)

		err := proto.sendTransactionList(peerID, newConversationID(), []*Transaction{})

		assert.NotNil(t, err)
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
