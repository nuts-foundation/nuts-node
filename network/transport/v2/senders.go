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
	"github.com/nuts-foundation/nuts-node/network/dag/tree"
	"github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/nuts-foundation/nuts-node/network/transport/grpc"
)

const transactionListMessageOverhead = 256
const transactionListTXOverhead = 8

type messageSender interface {
	sendGossipMsg(id transport.PeerID, refs []hash.SHA256Hash, xor hash.SHA256Hash, clock uint32) error
	sendTransactionListQuery(id transport.PeerID, refs []hash.SHA256Hash) error
	sendTransactionList(peerID transport.PeerID, conversationID conversationID, transactions []*Transaction) error
	sendTransactionRangeQuery(id transport.PeerID, lcStart uint32, lcEnd uint32) error
	sendState(id transport.PeerID, xor hash.SHA256Hash, clock uint32) error
	sendTransactionSet(id transport.PeerID, conversationID conversationID, LCReq uint32, LC uint32, iblt tree.Iblt) error
}

func (p *protocol) sendGossipMsg(id transport.PeerID, refs []hash.SHA256Hash, xor hash.SHA256Hash, clock uint32) error {
	conn := p.connectionList.Get(grpc.ByConnected(), grpc.ByPeerID(id))
	if conn == nil {
		return grpc.ErrNoConnection
	}

	// there shouldn't be more than a 100 in there, this will fit in a message
	refsAsBytes := make([][]byte, len(refs))
	for i, ref := range refs {
		refsAsBytes[i] = ref.Slice()
	}

	log.Logger().Tracef("GOSSIP: LC=%d, xor=%s, xor refs=%s, refs=%v", clock, xor, hash.EmptyHash().Xor(refs...), refs)

	return conn.Send(p, &Envelope{Message: &Envelope_Gossip{
		Gossip: &Gossip{
			XOR:          xor.Slice(),
			LC:           clock,
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

	msg := &Envelope_TransactionListQuery{
		TransactionListQuery: &TransactionListQuery{
			Refs: refsAsBytes,
		},
	}

	conversation := p.cMan.startConversation(msg)
	conversation.additionalInfo["refs"] = refs

	// todo convert to trace logging
	log.Logger().Infof("requesting transactionList from peer (peer=%s, conversationID=%s, #=%d)", id, conversation.conversationID.String(), len(refs))

	return conn.Send(p, &Envelope{Message: msg})
}

// sendTransactionList sorts transactions on LC value and filters private transaction payloads.
// It sends the resulting list to the peer
func (p *protocol) sendTransactionList(peerID transport.PeerID, conversationID conversationID, transactions []*Transaction) error {
	conn := p.connectionList.Get(grpc.ByConnected(), grpc.ByPeerID(peerID))
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

func (p *protocol) sendTransactionRangeQuery(id transport.PeerID, lcStart uint32, lcEnd uint32) error {
	conn := p.connectionList.Get(grpc.ByConnected(), grpc.ByPeerID(id))
	if conn == nil {
		return grpc.ErrNoConnection
	}
	msg := &Envelope_TransactionRangeQuery{
		TransactionRangeQuery: &TransactionRangeQuery{
			Start: lcStart,
			End:   lcEnd,
		},
	}
	cid := p.cMan.startConversation(msg)

	log.Logger().Debugf("requesting transaction range (peer=%s, conversationID=%s, start=%d, end=%d)", id.String(), cid.conversationID.String(), lcStart, lcEnd)

	return conn.Send(p, &Envelope{Message: msg})
}

// chunkTransactionList splits a large set of transactions into smaller sets. Each set adheres to the maximum message size.
func chunkTransactionList(transactions []*Transaction) [][]*Transaction {
	chunked := make([][]*Transaction, 0)

	currentSize := 0
	newSize := 0
	startIndex := 0
	endIndex := 0

	max := grpc.MaxMessageSizeInBytes - transactionListMessageOverhead

	for _, tx := range transactions {
		txSize := len(tx.Payload) + len(tx.Data) + transactionListTXOverhead
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

func (p *protocol) sendState(id transport.PeerID, xor hash.SHA256Hash, clock uint32) error {
	conn := p.connectionList.Get(grpc.ByConnected(), grpc.ByPeerID(id))
	if conn == nil {
		return grpc.ErrNoConnection
	}

	msg := &Envelope_State{
		State: &State{
			XOR: xor.Slice(),
			LC:  clock,
		},
	}
	conversation := p.cMan.startConversation(msg)

	// todo convert to trace logging
	log.Logger().Infof("requesting state from peer (peer=%s, conversationID=%s)", id, conversation.conversationID.String())

	return conn.Send(p, &Envelope{Message: msg})
}

func (p *protocol) sendTransactionSet(id transport.PeerID, conversationID conversationID, LCReq uint32, LC uint32, iblt tree.Iblt) error {
	conn := p.connectionList.Get(grpc.ByConnected(), grpc.ByPeerID(id))
	if conn == nil {
		return grpc.ErrNoConnection
	}

	ibltBytes, err := iblt.MarshalBinary()
	if err != nil {
		return err
	}

	return conn.Send(p, &Envelope{Message: &Envelope_TransactionSet{TransactionSet: &TransactionSet{
		ConversationID: conversationID.slice(),
		LCReq:          LCReq,
		LC:             LC,
		IBLT:           ibltBytes, // TODO: format of IBLT needs to be specced
	}}})
}
