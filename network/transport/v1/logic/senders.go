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
	"github.com/nuts-foundation/nuts-node/network/transport/v1/protobuf"
	"math"
	"time"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"google.golang.org/protobuf/proto"
)

// estimatedMessageSizeMargin defines the factor by which the message size is multiplied, as a safety measure to avoid
// accidentally exceeding the max Protobuf message size.
const estimatedMessageSizeMargin = 0.75

// messageSender provides a domain-specific abstraction for sending messages to the network. It aids testing and
// implementation of non-functional requirements like throttling.
type messageSender interface {
	broadcastAdvertHashes(blocks []dagBlock)
	broadcastDiagnostics(diagnostics transport.Diagnostics)
	broadcastTransactionPayloadQuery(payloadHash hash.SHA256Hash)
	sendTransactionListQuery(peer transport.PeerID, blockDate time.Time)
	sendTransactionList(peer transport.PeerID, transactions []dag.Transaction, date time.Time)
	sendTransactionPayloadQuery(peer transport.PeerID, payloadHash hash.SHA256Hash)
	sendTransactionPayload(peer transport.PeerID, payloadHash hash.SHA256Hash, data []byte)
}

type MessageGateway interface {
	Send(peer transport.PeerID, envelope *protobuf.NetworkMessage)
	Broadcast(envelope *protobuf.NetworkMessage)
}

type defaultMessageSender struct {
	gateway        MessageGateway
	maxMessageSize int
	transactionsPerMessage int
}

func (s defaultMessageSender) broadcastTransactionPayloadQuery(payloadHash hash.SHA256Hash) {
	s.gateway.Broadcast(createTransactionPayloadQueryMessage(payloadHash))
}

func (s defaultMessageSender) broadcastAdvertHashes(blocks []dagBlock) {
	envelope := createEnvelope()
	envelope.Message = createAdvertHashesMessage(blocks)
	s.gateway.Broadcast(&envelope)
}

func (s defaultMessageSender) broadcastDiagnostics(diagnostics transport.Diagnostics) {
	envelope := createEnvelope()
	message := protobuf.Diagnostics{
		Uptime:               uint32(diagnostics.Uptime.Seconds()),
		NumberOfTransactions: diagnostics.NumberOfTransactions,
		SoftwareVersion:      diagnostics.SoftwareVersion,
		SoftwareID:           diagnostics.SoftwareID,
	}
	for _, peer := range diagnostics.Peers {
		message.Peers = append(message.Peers, peer.String())
	}
	envelope.Message = &protobuf.NetworkMessage_DiagnosticsBroadcast{DiagnosticsBroadcast: &message}
	s.gateway.Broadcast(&envelope)
}

func (s defaultMessageSender) sendTransactionListQuery(peer transport.PeerID, blockDate time.Time) {
	envelope := createEnvelope()
	// TODO: timestamp=0 becomes disallowed when https://github.com/nuts-foundation/nuts-specification/issues/57 is implemented
	timestamp := int64(0)
	if !blockDate.IsZero() {
		timestamp = blockDate.Unix()
	}
	envelope.Message = &protobuf.NetworkMessage_TransactionListQuery{TransactionListQuery: &protobuf.TransactionListQuery{BlockDate: uint32(timestamp)}}
	s.gateway.Send(peer, &envelope)
}

func (s defaultMessageSender) sendTransactionList(peer transport.PeerID, transactions []dag.Transaction, blockDate time.Time) {
	if len(transactions) == 0 {
		// messages are asynchronous so the requester is not waiting for a response
		return
	}
	// When the DAG grows it the transactions might not fit in 1 network message (defined by p2p.MaxMessageSizeInBytes),
	// so we have to split it up in pages. Protobuf can calculate the size of a message, so we can check whether it will fit in the max. message size.
	// However, this can be quite expensive since it will marshal the message to the wire format (thus, marshalling will happen twice).
	// Furthermore, we'd have to do this for every transaction we add to the message to find the max. number of TXs that
	// will fit in the message.
	// Since this sounds all horribly inefficient, we just calculate the size of a network message with 1 transaction,
	// and use that to guesstimate the number of transactions that will fit in a message, decreased by a safety margin.
	// Since transactions just contain metadata of the transaction (and not the payload itself), all transactions should
	// serialize to more or less the same number of bytes, making the calculation safe.
	transactionsPerMessage := s.getTransactionsPerMessage(transactions)
	numberOfMessages := int(math.Ceil(float64(len(transactions)) / float64(transactionsPerMessage)))
	tl := toNetworkTransactions(transactions)

	for i := 0; i < numberOfMessages; i++ {
		upper := (i + 1) * transactionsPerMessage
		if upper > len(tl) {
			upper = len(tl)
		}
		envelope := createEnvelope()
		envelope.Message = &protobuf.NetworkMessage_TransactionList{TransactionList: &protobuf.TransactionList{Transactions: tl[i*transactionsPerMessage : upper], BlockDate: uint32(blockDate.Unix())}}
		s.gateway.Send(peer, &envelope)
	}
}

func (s defaultMessageSender) sendTransactionPayloadQuery(peer transport.PeerID, payloadHash hash.SHA256Hash) {
	s.gateway.Send(peer, createTransactionPayloadQueryMessage(payloadHash))
}

func (s defaultMessageSender) sendTransactionPayload(peer transport.PeerID, payloadHash hash.SHA256Hash, data []byte) {
	envelope := createEnvelope()
	envelope.Message = &protobuf.NetworkMessage_TransactionPayload{TransactionPayload: &protobuf.TransactionPayload{
		PayloadHash: payloadHash.Slice(),
		Data:        data,
	}}
	s.gateway.Send(peer, &envelope)
}

func (s defaultMessageSender) getTransactionsPerMessage(transactions []dag.Transaction) int {
	if s.transactionsPerMessage != 0 {
		return s.transactionsPerMessage
	}

	sizeMsg := createEnvelope()
	sizeMsg.Message = &protobuf.NetworkMessage_TransactionList{TransactionList: &protobuf.TransactionList{Transactions: toNetworkTransactions([]dag.Transaction{transactions[0]}), BlockDate: uint32(time.Now().Unix())}}
	messageSizePerTX := proto.Size(sizeMsg.ProtoReflect().Interface())
	s.transactionsPerMessage = int(math.Floor(float64(s.maxMessageSize) * estimatedMessageSizeMargin / float64(messageSizePerTX)))
	return s.transactionsPerMessage
}

func createEnvelope() protobuf.NetworkMessage {
	return protobuf.NetworkMessage{}
}

func createTransactionPayloadQueryMessage(payloadHash hash.SHA256Hash) *protobuf.NetworkMessage {
	envelope := createEnvelope()
	envelope.Message = &protobuf.NetworkMessage_TransactionPayloadQuery{
		TransactionPayloadQuery: &protobuf.TransactionPayloadQuery{PayloadHash: payloadHash.Slice()},
	}
	return &envelope
}

func createAdvertHashesMessage(blocks []dagBlock) *protobuf.NetworkMessage_AdvertHashes {
	protoBlocks := make([]*protobuf.BlockHashes, len(blocks)-1)
	for blockIdx, currBlock := range blocks {
		// First block = historic block, which isn't added in full but as XOR of its heads
		if blockIdx > 0 {
			protoBlocks[blockIdx-1] = &protobuf.BlockHashes{Hashes: make([][]byte, len(currBlock.heads))}
			for headIdx, currHead := range currBlock.heads {
				protoBlocks[blockIdx-1].Hashes[headIdx] = currHead.Slice()
			}
		}
	}
	historicBlock := getHistoricBlock(blocks) // First block is historic block
	currentBlock := getCurrentBlock(blocks)   // Last block is current block
	return &protobuf.NetworkMessage_AdvertHashes{AdvertHashes: &protobuf.AdvertHashes{
		Blocks:           protoBlocks,
		HistoricHash:     historicBlock.xor().Slice(),
		CurrentBlockDate: getBlockTimestamp(currentBlock.start),
	}}
}
