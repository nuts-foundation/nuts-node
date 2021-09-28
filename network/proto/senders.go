package proto

import (
	"math"
	"time"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/network/p2p"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"google.golang.org/protobuf/proto"
)

// estimatedMessageSizeMargin defines the factor by which the message size is multiplied, as a safety measure to avoid
// accidentally exceeding the max Protobuf message size.
const estimatedMessageSizeMargin = 0.75

// messageSender provides a domain-specific abstraction for sending messages to the network. It aids testing and
// implementation of non-functional requirements like throttling.
type messageSender interface {
	broadcastAdvertHashes(blocks []dagBlock)
	broadcastDiagnostics(diagnostics Diagnostics)
	broadcastTransactionPayloadQuery(payloadHash hash.SHA256Hash)
	sendTransactionListQuery(peer p2p.PeerID, blockDate time.Time)
	sendTransactionList(peer p2p.PeerID, transactions []dag.Transaction, date time.Time)
	sendTransactionPayloadQuery(peer p2p.PeerID, payloadHash hash.SHA256Hash)
	sendTransactionPayload(peer p2p.PeerID, payloadHash hash.SHA256Hash, data []byte)
}

type defaultMessageSender struct {
	p2p                    p2p.Adapter
	maxMessageSize         int
	transactionsPerMessage int
}

func (s defaultMessageSender) doSend(peer p2p.PeerID, envelope *transport.NetworkMessage) {
	if err := s.p2p.Send(peer, envelope); err != nil {
		log.Logger().Warnf("Error while sending message to peer (peer=%s, msg=%T): %v", peer, envelope.Message, err)
	}
}

func (s defaultMessageSender) broadcastTransactionPayloadQuery(payloadHash hash.SHA256Hash) {
	s.p2p.Broadcast(createTransactionPayloadQueryMessage(payloadHash))
}

func (s defaultMessageSender) broadcastAdvertHashes(blocks []dagBlock) {
	envelope := createEnvelope()
	envelope.Message = createAdvertHashesMessage(blocks)
	s.p2p.Broadcast(&envelope)
}

func (s defaultMessageSender) broadcastDiagnostics(diagnostics Diagnostics) {
	envelope := createEnvelope()
	message := transport.Diagnostics{
		Uptime:               uint32(diagnostics.Uptime.Seconds()),
		NumberOfTransactions: diagnostics.NumberOfTransactions,
		SoftwareVersion:      diagnostics.SoftwareVersion,
		SoftwareID:           diagnostics.SoftwareID,
	}
	for _, peer := range diagnostics.Peers {
		message.Peers = append(message.Peers, peer.String())
	}
	envelope.Message = &transport.NetworkMessage_DiagnosticsBroadcast{DiagnosticsBroadcast: &message}
	s.p2p.Broadcast(&envelope)
}

func (s defaultMessageSender) sendTransactionListQuery(peer p2p.PeerID, blockDate time.Time) {
	envelope := createEnvelope()
	// TODO: timestamp=0 becomes disallowed when https://github.com/nuts-foundation/nuts-specification/issues/57 is implemented
	timestamp := int64(0)
	if !blockDate.IsZero() {
		timestamp = blockDate.Unix()
	}
	envelope.Message = &transport.NetworkMessage_TransactionListQuery{TransactionListQuery: &transport.TransactionListQuery{BlockDate: uint32(timestamp)}}
	s.doSend(peer, &envelope)
}

func (s defaultMessageSender) sendTransactionList(peer p2p.PeerID, transactions []dag.Transaction, blockDate time.Time) {
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
		envelope.Message = &transport.NetworkMessage_TransactionList{TransactionList: &transport.TransactionList{Transactions: tl[i*transactionsPerMessage : upper], BlockDate: uint32(blockDate.Unix())}}
		s.doSend(peer, &envelope)
	}
}

func (s defaultMessageSender) sendTransactionPayloadQuery(peer p2p.PeerID, payloadHash hash.SHA256Hash) {
	s.doSend(peer, createTransactionPayloadQueryMessage(payloadHash))
}

func (s defaultMessageSender) sendTransactionPayload(peer p2p.PeerID, payloadHash hash.SHA256Hash, data []byte) {
	envelope := createEnvelope()
	envelope.Message = &transport.NetworkMessage_TransactionPayload{TransactionPayload: &transport.TransactionPayload{
		PayloadHash: payloadHash.Slice(),
		Data:        data,
	}}
	s.doSend(peer, &envelope)
}

func (s defaultMessageSender) getTransactionsPerMessage(transactions []dag.Transaction) int {
	if s.transactionsPerMessage != 0 {
		return s.transactionsPerMessage
	}

	sizeMsg := createEnvelope()
	sizeMsg.Message = &transport.NetworkMessage_TransactionList{TransactionList: &transport.TransactionList{Transactions: toNetworkTransactions([]dag.Transaction{transactions[0]}), BlockDate: uint32(time.Now().Unix())}}
	messageSizePerTX := proto.Size(sizeMsg.ProtoReflect().Interface())
	s.transactionsPerMessage = int(math.Floor(float64(s.maxMessageSize) * estimatedMessageSizeMargin / float64(messageSizePerTX)))
	return s.transactionsPerMessage
}

func createEnvelope() transport.NetworkMessage {
	return transport.NetworkMessage{}
}

func createTransactionPayloadQueryMessage(payloadHash hash.SHA256Hash) *transport.NetworkMessage {
	envelope := createEnvelope()
	envelope.Message = &transport.NetworkMessage_TransactionPayloadQuery{
		TransactionPayloadQuery: &transport.TransactionPayloadQuery{PayloadHash: payloadHash.Slice()},
	}
	return &envelope
}
