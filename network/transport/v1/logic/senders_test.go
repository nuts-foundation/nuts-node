/*
 * Copyright (C) 2021 Nuts community
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

package logic

import (
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/nuts-foundation/nuts-node/network/transport/grpc"
	"github.com/nuts-foundation/nuts-node/network/transport/v1/protobuf"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/stretchr/testify/assert"
)

func createMessageSender(t *testing.T) (defaultMessageSender, *MockMessageGateway) {
	ctrl := gomock.NewController(t)
	t.Cleanup(func() {
		ctrl.Finish()
	})
	gateway := NewMockMessageGateway(ctrl)
	sender := defaultMessageSender{gateway: gateway}
	sender.maxMessageSize = grpc.MaxMessageSizeInBytes
	return sender, gateway
}

func Test_defaultMessageSender_broadcastAdvertHashes(t *testing.T) {
	sender, mock := createMessageSender(t)
	now := time.Now()
	hash1 := hash.SHA256Sum([]byte{1})
	mock.EXPECT().Broadcast(&protobuf.NetworkMessage{Message: &protobuf.NetworkMessage_AdvertHashes{AdvertHashes: &protobuf.AdvertHashes{
		CurrentBlockDate: uint32(now.Unix()),
		Blocks:           []*protobuf.BlockHashes{{Hashes: [][]byte{hash1.Slice()}}},
		HistoricHash:     hash.EmptyHash().Slice(),
	}}})
	sender.broadcastAdvertHashes([]dagBlock{
		{start: time.Time{}},
		{start: now, heads: []hash.SHA256Hash{hash1}},
	},
	)
}

func Test_defaultMessageSender_broadcastDiagnostics(t *testing.T) {
	sender, mock := createMessageSender(t)
	mock.EXPECT().Broadcast(&protobuf.NetworkMessage{Message: &protobuf.NetworkMessage_DiagnosticsBroadcast{DiagnosticsBroadcast: &protobuf.Diagnostics{
		Uptime:               1000,
		Peers:                []string{"foobar"},
		NumberOfTransactions: 5,
		SoftwareVersion:      "1.0",
		SoftwareID:           "Test",
	}}})
	sender.broadcastDiagnostics(transport.Diagnostics{
		Uptime:               1000 * time.Second,
		Peers:                []transport.PeerID{"foobar"},
		NumberOfTransactions: 5,
		SoftwareVersion:      "1.0",
		SoftwareID:           "Test",
	})
}

func Test_defaultMessageSender_sendTransactionList(t *testing.T) {
	blockDate := time.Date(2021, 4, 29, 0, 0, 0, 0, time.UTC)

	t.Run("ok", func(t *testing.T) {
		sender, mock := createMessageSender(t)
		tx := testTX{data: []byte{1, 2, 3}}
		mock.EXPECT().Send(peerID, &protobuf.NetworkMessage{Message: &protobuf.NetworkMessage_TransactionList{TransactionList: &protobuf.TransactionList{
			BlockDate: uint32(blockDate.Unix()),
			Transactions: []*protobuf.Transaction{{
				Hash: tx.Ref().Slice(),
				Data: tx.data,
			}},
		}}})
		sender.sendTransactionList(peerID, []dag.Transaction{tx}, blockDate)
	})
	t.Run("ok - paginated", func(t *testing.T) {
		// This test checks whether transaction list responses that exceed the maximum Protobuf message size are split into
		// pages.
		const numberOfTXs = 100     // number of transactions this test produces
		const maxMessageSize = 6000 // max. message size in bytes
		const dataSize = 100        // number of bytes added to the TX to make them a bit larger
		const numberOfMessages = 4  // expected number of pages when the transaction list is sent

		var txs []dag.Transaction
		for i := 0; i < numberOfTXs; i++ {
			data := make([]byte, dataSize)
			txs = append(txs, &testTX{data: append([]byte{byte(i)}, data...)})
		}

		sender, mock := createMessageSender(t)
		sender.maxMessageSize = maxMessageSize
		sentMessages := map[byte]bool{}
		mock.EXPECT().Send(peerID, gomock.Any()).DoAndReturn(func(_ transport.PeerID, msg *protobuf.NetworkMessage) error {
			for _, tx := range msg.GetTransactionList().Transactions {
				if sentMessages[tx.Data[0]] {
					t.Fatalf("transaction sent twice (idx: %d)", tx.Data[0])
				}
				sentMessages[tx.Data[0]] = true
			}
			return nil
		}).Times(numberOfMessages)
		sender.sendTransactionList(peerID, txs, blockDate)

		assert.Len(t, sentMessages, numberOfTXs)
		for i := 0; i < numberOfTXs; i++ {
			if !sentMessages[byte(i)] {
				t.Fatalf("Missing message (idx: %d)", i)
			}
		}
	})
	t.Run("ok - no transactions sends nothing", func(t *testing.T) {
		sender, _ := createMessageSender(t)
		sender.sendTransactionList(peerID, []dag.Transaction{}, blockDate)
	})
}

func Test_defaultMessageSender_sendTransactionListQuery(t *testing.T) {
	t.Run("block date is set", func(t *testing.T) {
		sender, mock := createMessageSender(t)
		moment := time.Now()
		mock.EXPECT().Send(peerID, &protobuf.NetworkMessage{Message: &protobuf.NetworkMessage_TransactionListQuery{TransactionListQuery: &protobuf.TransactionListQuery{BlockDate: uint32(moment.Unix())}}})
		sender.sendTransactionListQuery(peerID, moment)
	})
	t.Run("block date is zero", func(t *testing.T) {
		sender, mock := createMessageSender(t)
		mock.EXPECT().Send(peerID, &protobuf.NetworkMessage{Message: &protobuf.NetworkMessage_TransactionListQuery{TransactionListQuery: &protobuf.TransactionListQuery{BlockDate: 0}}})
		sender.sendTransactionListQuery(peerID, time.Time{})
	})
}

func Test_defaultMessageSender_sendTransactionPayload(t *testing.T) {
	sender, mock := createMessageSender(t)
	payload := []byte{1, 2, 3}
	payloadHash := hash.SHA256Sum(payload)
	mock.EXPECT().Send(peerID, &protobuf.NetworkMessage{Message: &protobuf.NetworkMessage_TransactionPayload{TransactionPayload: &protobuf.TransactionPayload{
		PayloadHash: payloadHash.Slice(),
		Data:        payload,
	}}})
	sender.sendTransactionPayload(peerID, payloadHash, payload)
}

func Test_defaultMessageSender_sendTransactionPayloadQuery(t *testing.T) {
	sender, mock := createMessageSender(t)
	payloadHash := hash.SHA256Sum([]byte{1, 2, 3})
	mock.EXPECT().Send(peerID, &protobuf.NetworkMessage{Message: &protobuf.NetworkMessage_TransactionPayloadQuery{TransactionPayloadQuery: &protobuf.TransactionPayloadQuery{PayloadHash: payloadHash.Slice()}}})
	sender.sendTransactionPayloadQuery(peerID, payloadHash)
}
