/*
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
	"context"
	"errors"
	"fmt"
	"math"
	"sort"

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
	case *Envelope_Gossip:
		logMessage(msg)
		return p.handleGossip(peer, msg.Gossip)
	case *Envelope_Hello:
		logMessage(msg)
		log.Logger().Infof("%T: %s said hello", p, peer)
		return nil
	case *Envelope_TransactionList:
		logMessage(msg)
		return p.handleTransactionList(peer, msg)
	case *Envelope_TransactionListQuery:
		logMessage(msg)
		return p.handleTransactionListQuery(peer, msg.TransactionListQuery)
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
	tx, err := p.state.GetTransaction(ctx, hash.FromSlice(msg.TransactionRef))
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

	data, err := p.state.ReadPayload(ctx, tx.PayloadHash())
	if err != nil {
		return err
	}
	return p.send(peer, &Envelope_TransactionPayload{TransactionPayload: &TransactionPayload{TransactionRef: msg.TransactionRef, Data: data}})
}

func (p *protocol) handleTransactionPayload(msg *TransactionPayload) error {
	ctx := context.Background()
	ref := hash.FromSlice(msg.TransactionRef)
	if ref.Empty() {
		return errors.New("msg is missing transaction reference")
	}
	if len(msg.Data) == 0 {
		return fmt.Errorf("peer does not have transaction payload (tx=%s)", ref)
	}
	tx, err := p.state.GetTransaction(ctx, ref)
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
	if err = p.state.WritePayload(ctx, payloadHash, msg.Data); err != nil {
		return err
	}

	// it's saved, remove the job
	return p.payloadScheduler.Finished(ref)
}

func (p *protocol) handleGossip(peer transport.Peer, msg *Gossip) error {
	refs := make([]hash.SHA256Hash, len(msg.Transactions))
	i := 0
	ctx := context.Background()
	for _, bytes := range msg.Transactions {
		ref := hash.FromSlice(bytes)
		// separate reader transactions on DB but that's ok.
		present, err := p.state.IsPresent(ctx, ref)
		if err != nil {
			return fmt.Errorf("failed to handle Gossip message: %w", err)
		}
		if !present {
			refs[i] = ref
			i++
		}
	}
	refs = refs[:i]
	if len(refs) > 0 {
		// TODO swap for trace logging
		log.Logger().Infof("received %d new transaction references via Gossip", len(refs))
		p.sender.sendTransactionListQuery(peer.ID, refs)
	}
	p.gManager.GossipReceived(peer.ID, refs...)

	xor, _ := p.state.XOR(ctx, math.MaxUint32)
	xor = xor.Xor(refs...)
	if xor.Equals(hash.FromSlice(msg.GetXOR())) {
		return nil
	}

	// TODO send state message
	log.Logger().Infof("xor is different from peer=%s", peer.ID)

	return nil
}

func (p *protocol) handleTransactionList(peer transport.Peer, envelope *Envelope_TransactionList) error {
	msg := envelope.TransactionList
	cid := conversationID(msg.ConversationID)
	conversation := p.cMan.conversations[cid.String()]

	// TODO convert to trace logging
	log.Logger().Infof("handling handleTransactionList from peer (peer=%s, conversationID=%s)", peer.ID.String(), cid.String())

	// check if response matches earlier request
	if err := p.cMan.check(envelope); err != nil {
		return err
	}

	refsToBeRemoved := map[string]bool{}
	ctx := context.Background()
	for _, tx := range msg.Transactions {
		transactionRef := hash.FromSlice(tx.Hash)
		transaction, err := dag.ParseTransaction(tx.Data)
		if err != nil {
			return fmt.Errorf("received transaction is invalid (peer=%s, ref=%s): %w", peer, transactionRef, err)
		}

		present, err := p.state.IsPresent(ctx, transactionRef)
		if err != nil {
			return fmt.Errorf("unable to add received transaction to DAG (tx=%s): %w", transaction.Ref(), err)
		}
		if !present {
			// TODO does this always trigger fetching missing payloads? (through observer on DAG) Prolly not for v2
			if err = p.state.Add(ctx, transaction, tx.Payload); err != nil {
				return fmt.Errorf("unable to add received transaction to DAG (tx=%s): %w", transaction.Ref(), err)
			}
		}
		refsToBeRemoved[transactionRef.String()] = true
	}

	// remove from conversation
	if conversation.additionalInfo["refs"] != nil {
		requestedRefs := conversation.additionalInfo["refs"].([]hash.SHA256Hash)
		newRefs := make([]hash.SHA256Hash, len(requestedRefs))
		i := 0
		for _, requestedRef := range requestedRefs {
			if _, ok := refsToBeRemoved[requestedRef.String()]; !ok {
				newRefs[i] = requestedRef
				i++
			}
		}
		newRefs = newRefs[:i]
		conversation.additionalInfo["refs"] = newRefs

		// if len == 0, mark as done
		if len(newRefs) == 0 {
			p.cMan.done(cid)
		}
	}

	return nil
}

func (p *protocol) handleTransactionListQuery(peer transport.Peer, msg *TransactionListQuery) error {
	requestedRefs := make([]hash.SHA256Hash, len(msg.Refs))
	unsorted := make([]dag.Transaction, 0)

	cid := conversationID(msg.ConversationID)

	// TODO convert to trace logging
	log.Logger().Infof("handling transactionListQuery from peer (peer=%s, conversationID=%s)", peer.ID.String(), cid.String())

	for i, refBytes := range msg.Refs {
		requestedRefs[i] = hash.FromSlice(refBytes)
	}

	if len(requestedRefs) == 0 {
		log.Logger().Warnf("peer sent request for 0 transactions (peer=%s)", peer.ID)
		return nil
	}

	ctx := context.Background()

	// first retrieve all transactions, this is needed to sort them on LC value
	for _, ref := range requestedRefs {
		transaction, err := p.state.GetTransaction(ctx, ref)
		if err != nil {
			return err
		}
		// If a transaction is not present, we stop any further transaction gathering.
		if transaction != nil {
			unsorted = append(unsorted, transaction)
		} else {
			log.Logger().Warnf("peer requested transaction we don't have (peer=%s, node=%s, ref=%s)", peer.ID, peer.NodeDID.String(), ref.String())
		}
	}

	// now we sort on LC value
	sort.Slice(unsorted, func(i, j int) bool {
		return unsorted[i].Clock() <= unsorted[j].Clock()
	})

	transactions := make([]*Transaction, 0)
	for _, transaction := range unsorted {
		networkTX := Transaction{
			Hash: transaction.Ref().Slice(),
			Data: transaction.Data(),
		}

		// do not add private TX payloads
		if len(transaction.PAL()) == 0 {
			payload, err := p.state.ReadPayload(ctx, transaction.PayloadHash())
			if err != nil {
				return err
			}
			// TODO we abort here as well, since there's no mechanism for missing payloads on public transactions in v2 protocol
			if payload == nil {
				log.Logger().Warnf("peer requested transaction with missing payload (peer=%s, node=%s, ref=%s)", peer.ID, peer.NodeDID.String(), transaction.Ref().String())
				break
			}
			networkTX.Payload = payload
		}
		transactions = append(transactions, &networkTX)
	}

	return p.sender.sendTransactionList(peer.ID, cid, transactions)
}
