package v2

import (
	"context"
	"errors"
	"fmt"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/network/transport"
)

func (p protocol) Handle(peer transport.Peer, raw interface{}) error {
	envelope := raw.(*Envelope)

	logMessage := func(msg interface{}) {
		log.Logger().Tracef("Handling %T from peer: %s", msg, peer)
	}

	switch msg := envelope.Message.(type) {
	case *Envelope_Hello:
		logMessage(msg)
		log.Logger().Infof("%T: %s said hello", p, peer)
		return nil
	case *Envelope_TransactionPayloadQuery:
		logMessage(msg)
		return p.handleTransactionPayloadQuery(peer, msg.TransactionPayloadQuery)
	case *Envelope_TransactionPayload:
		logMessage(msg)
		return p.handleTransactionPayload(msg.TransactionPayload)
	}

	return errors.New("envelope doesn't contain any (handleable) messages")
}

func (p *protocol) handleTransactionPayloadQuery(peer transport.Peer, msg *TransactionPayloadQuery) error {
	ctx := context.Background()
	tx, err := p.graph.Get(ctx, hash.FromSlice(msg.TransactionRef))
	if err != nil {
		return err
	}
	emptyResponse := &Envelope_TransactionPayload{TransactionPayload: &TransactionPayload{TransactionRef: msg.TransactionRef}}
	if tx == nil {
		// Transaction not found
		return p.send(peer, emptyResponse)
	}
	if len(tx.PAL()) > 0 {
		// Private TX, verify connection
		if peer.NodeDID.Empty() {
			// Connection isn't authenticated
			log.Logger().Warnf("Peer requested private transaction over unauthenticated connection (peer=%s,tx=%s)", peer, tx.Ref())
			return p.send(peer, emptyResponse)
		}
		epal := dag.EncryptedPAL(tx.PAL())

		pal, err := p.decryptPAL(epal)
		if err != nil {
			log.Logger().Errorf("Peer requested private transaction but decoding failed (peer=%s,tx=%s): %v", peer, tx.Ref(), err)
			return p.send(peer, emptyResponse)
		}

		// We weren't able to decrypt the PAL, so it wasn't meant for us
		if pal == nil {
			log.Logger().Warnf("Peer requested private transaction we can't decode (peer=%s,tx=%s)", peer, tx.Ref())
			return p.send(peer, emptyResponse)
		}

		if !pal.Contains(peer.NodeDID) {
			log.Logger().Warnf("Peer requested private transaction illegally (peer=%s,tx=%s)", peer, tx.Ref())
			return p.send(peer, emptyResponse)
		}
		// successful assertions fall through
	}

	data, err := p.payloadStore.ReadPayload(ctx, tx.PayloadHash())
	if err != nil {
		return err
	}
	return p.send(peer, &Envelope_TransactionPayload{TransactionPayload: &TransactionPayload{TransactionRef: msg.TransactionRef, Data: data}})
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
	if err = p.payloadStore.WritePayload(ctx, payloadHash, msg.Data); err != nil {
		return err
	}

	// it's saved, remove the job
	return p.payloadScheduler.Finished(ref)
}
