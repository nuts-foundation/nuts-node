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
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/nuts-foundation/nuts-node/network/transport/grpc"
)

func (p *protocol) sendGossipMsg(id transport.PeerID, refs []hash.SHA256Hash) error {
	conn := p.connectionList.Get(grpc.ByConnected(), grpc.ByPeerID(id))
	if conn == nil {
		return grpc.ErrNoConnection
	}

	// there shouldn't be more than a 100 in there, this will fit in a message
	refsAsBytes := make([][]byte, len(refs))
	for i, ref := range refs {
		refsAsBytes[i] = ref.Slice()
	}

	return conn.Send(p, &Envelope{Message: &Envelope_Gossip{
		Gossip: &Gossip{
			Transactions: refsAsBytes,
		},
	}})
}

func (p *protocol) sendTransactionListQuery(id transport.PeerID, refs []hash.SHA256Hash) error {
	conn := p.connectionList.Get(grpc.ByConnected(), grpc.ByPeerID(id))
	if conn == nil {
		return grpc.ErrNoConnection
	}

	// there shouldn't be more than ~650 in there, this will fit in a single message
	// 650 is based on the maximum number of TXs that can be determined by a single IBLT decode operation.
	// Any mismatches beyond that point will be handled by TransactionRangeQueries
	refsAsBytes := make([][]byte, len(refs))
	for i, ref := range refs {
		refsAsBytes[i] = ref.Slice()
	}

	envelope := &Envelope_TransactionListQuery{
		TransactionListQuery: &TransactionListQuery{
			Refs: refsAsBytes,
		},
	}

	conversation := p.cMan.startConversation(envelope)
	conversation.additionalInfo["refs"] = refs

	// todo convert to trace logging
	log.Logger().Infof("requesting transactions from peer (peer=%s, conversationID=%s)", id, conversation.conversationID.String())

	return conn.Send(p, &Envelope{Message: envelope})
}

func (p *protocol) sendTransactionList(id transport.PeerID, conversationID conversationID, transactions []*Transaction) error {
	conn := p.connectionList.Get(grpc.ByConnected(), grpc.ByPeerID(id))
	if conn == nil {
		return grpc.ErrNoConnection
	}

	for _, chunk := range chunkTransactionList(transactions) {
		if err := conn.Send(p, &Envelope{Message: &Envelope_TransactionList{
			TransactionList: &TransactionList{
				ConversationID: conversationID.slice(),
				Transactions:   chunk,
			},
		}}); err != nil {
			return err
		}
	}

	return nil
}

// chunkTransactionList splits a large set of transactions into smaller sets. Each set adheres to the maximum message size.
func chunkTransactionList(transactions []*Transaction) [][]*Transaction {
	chunked := make([][]*Transaction, 0)

	currentSize := 0
	newSize := 0
	startIndex := 0
	endIndex := 0

	// TODO to be tested in practise
	max := grpc.MaxMessageSizeInBytes - 256 // 256 chosen as overhead per message

	for _, tx := range transactions {
		txSize := len(tx.Hash) + len(tx.Payload) + len(tx.Data)
		newSize = currentSize + txSize

		if newSize > max {
			chunked = append(chunked, transactions[startIndex:endIndex])
			currentSize = txSize
			startIndex = endIndex
		} else {
			currentSize = newSize
		}
		endIndex++
	}

	// any trailing messages
	if startIndex != len(transactions) {
		chunked = append(chunked, transactions[startIndex:])
	}

	return chunked
}
