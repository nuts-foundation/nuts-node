package proto

import (
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/network/p2p"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"time"
)

// messageSender provides a domain-specific abstraction for sending messages to the network. It aids testing and
// implementation of non-functional requirements like throttling.
type messageSender interface {
	broadcastAdvertHashes(blocks []dagBlock)
	sendTransactionListQuery(peer p2p.PeerID, blockDate time.Time)
	sendTransactionList(peer p2p.PeerID, transactions []dag.Transaction)
	sendTransactionPayloadQuery(peer p2p.PeerID, payloadHash hash.SHA256Hash)
	sendTransactionPayload(peer p2p.PeerID, payloadHash hash.SHA256Hash, data []byte)
}

type defaultMessageSender struct {
	p2p p2p.Adapter
}

func (s defaultMessageSender) doSend(peer p2p.PeerID, envelope *transport.NetworkMessage) {
	if err := s.p2p.Send(peer, envelope); err != nil {
		log.Logger().Warnf("Error while sending message to peer (peer=%s, msg=%T): %v", peer, envelope.Message, err)
	}
}

func (s defaultMessageSender) broadcastAdvertHashes(blocks []dagBlock) {
	envelope := createEnvelope()
	envelope.Message = createAdvertHashesMessage(blocks)
	s.p2p.Broadcast(&envelope)
}

func (s defaultMessageSender) sendTransactionListQuery(peer p2p.PeerID, blockDate time.Time) {
	envelope := createEnvelope()
	// TODO: timestamp=0 becomes disallowed when https://github.com/nuts-foundation/nuts-specification/issues/57 is implemented
	timestamp := int64(0)
	if !blockDate.IsZero() {
		timestamp = blockDate.UTC().Unix()
	}
	envelope.Message = &transport.NetworkMessage_TransactionListQuery{TransactionListQuery: &transport.TransactionListQuery{BlockDate: uint32(timestamp)}}
	s.doSend(peer, &envelope)
}

func (s defaultMessageSender) sendTransactionList(peer p2p.PeerID, transactions []dag.Transaction) {
	envelope := createEnvelope()
	tl := toNetworkTransactions(transactions)
	envelope.Message = &transport.NetworkMessage_TransactionList{TransactionList: &transport.TransactionList{Transactions: tl}}
	s.doSend(peer, &envelope)
}

func (s defaultMessageSender) sendTransactionPayloadQuery(peer p2p.PeerID, payloadHash hash.SHA256Hash) {
	envelope := createEnvelope()
	envelope.Message = &transport.NetworkMessage_TransactionPayloadQuery{
		TransactionPayloadQuery: &transport.TransactionPayloadQuery{PayloadHash: payloadHash.Slice()},
	}
	s.doSend(peer, &envelope)
}

func (s defaultMessageSender) sendTransactionPayload(peer p2p.PeerID, payloadHash hash.SHA256Hash, data []byte) {
	envelope := createEnvelope()
	envelope.Message = &transport.NetworkMessage_TransactionPayload{TransactionPayload: &transport.TransactionPayload{
		PayloadHash: payloadHash.Slice(),
		Data:        data,
	}}
	s.doSend(peer, &envelope)
}

func createEnvelope() transport.NetworkMessage {
	return transport.NetworkMessage{}
}
