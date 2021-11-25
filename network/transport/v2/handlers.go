package v2

import (
	"context"
	"errors"
	"fmt"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/network/transport"
)

var handleErrorLogger = func(msg interface{}, peer transport.Peer, err error) {
	log.Logger().Errorf("Error handling %T (peer=%s): %v", msg, peer, err)
}

func (p protocol) handle(peer transport.Peer, envelope *Envelope, reply func(msg isEnvelope_Message) error) {
	var handled bool

	logMessage := func(msg interface{}) {
		log.Logger().Tracef("Handling %T from peer: %s", msg, peer)
	}

	switch msg := envelope.Message.(type) {
	case *Envelope_Hello:
		logMessage(msg)
		log.Logger().Infof("%T: %s said hello", p, peer)
		handled = true
	case *Envelope_TransactionPayloadQuery:
		logMessage(msg)
		handled = true
		err := p.handleTransactionPayloadQuery(msg.TransactionPayloadQuery, reply, peer)
		if err != nil {
			handleErrorLogger(msg, peer, err)
		}
	case *Envelope_TransactionPayload:
		logMessage(msg)
		handled = true
		err := p.handleTransactionPayload(msg.TransactionPayload)
		if err != nil {
			handleErrorLogger(msg, peer, err)
		}
	}

	if !handled {
		log.Logger().Warnf("%T: Envelope doesn't contain any (handleable) messages, peer sent an empty message or protocol implementation might differ? (peer=%s)", p, peer)
	}
}

func (p *protocol) handleTransactionPayloadQuery(msg *TransactionPayloadQuery, reply func(msg isEnvelope_Message) error, peer transport.Peer) error {
	ctx := context.Background()
	tx, err := p.graph.Get(ctx, hash.FromSlice(msg.TransactionRef))
	if err != nil {
		return err
	}
	emptyResponse := &Envelope_TransactionPayload{TransactionPayload: &TransactionPayload{TransactionRef: msg.TransactionRef}}
	if tx == nil {
		// Transaction not found
		return reply(emptyResponse)
	}
	if len(tx.PAL()) > 0 {
		// Private TX, verify connection
		if peer.NodeDID.Empty() {
			// Connection isn't authenticated
			log.Logger().Warnf("Peer requested private transaction over unauthenticated connection (peer=%s,tx=%s)", peer, tx.Ref())
			return reply(emptyResponse)
		}
		// TODO: Authorize node DID using PAL header
		log.Logger().Error("TODO: Querying private transaction in v2 is not supported yet.")
		return reply(emptyResponse)
	}

	data, err := p.payloadStore.ReadPayload(ctx, tx.PayloadHash())
	if err != nil {
		return err
	}
	return reply(&Envelope_TransactionPayload{TransactionPayload: &TransactionPayload{TransactionRef: msg.TransactionRef, Data: data}})
}

func (p protocol) handleTransactionPayload(msg *TransactionPayload) error {
	ctx := context.Background()
	ref := hash.FromSlice(msg.TransactionRef)
	if ref.Empty() {
		return errors.New("message is missing transaction reference")
	}
	if len(msg.Data) == 0 {
		return fmt.Errorf("peer does not have transaction payload (tx=%s)", ref)
	}
	tx, err := p.graph.Get(ctx, ref)
	if err != nil {
		return err
	}
	if tx == nil {
		// Weird case: transaction not present on DAG (might be attack attempt).
		return fmt.Errorf("peer sent payload for non-existing transaction (tx=%s)", ref)
	}
	payloadHash := hash.SHA256Sum(msg.Data)
	if !tx.PayloadHash().Equals(payloadHash) {
		// Possible attack: received payload does not match transaction payload hash.
		return fmt.Errorf("peer sent payload that doesn't match payload hash (tx=%s)", ref)
	}
	return p.payloadStore.WritePayload(ctx, payloadHash, msg.Data)
}
