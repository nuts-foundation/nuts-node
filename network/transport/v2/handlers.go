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
	"github.com/nuts-foundation/nuts-node/network/dag/tree"
	"github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/network/transport"
)

// errInternalError is returned to the node's peer when an internal error occurs.
var errInternalError = errors.New("internal error")

// errMessageNotSupported is returned to the node's peer when the received message is not supported.
var errMessageNotSupported = errors.New("message not supported")

// allowedErrors is a list of errors that are allowed to be sent back to the peer (spec'd by RFC017).
var allowedErrors = []error{
	errInternalError,
	errMessageNotSupported,
}

func (p *protocol) Handle(peer transport.Peer, raw interface{}) error {
	envelope := raw.(*Envelope)
	log.Logger().Tracef("Handling %T from peer: %s", envelope.Message, peer)

	err := p.handle(peer, envelope)
	if err != nil {
		log.Logger().Errorf("Error handling %T (peer=%s): %s", envelope.Message, peer, err)
		// Only return allowed errors
		for _, allowedError := range allowedErrors {
			if err == allowedError {
				return err
			}
		}
		// If the error isn't allowed to be returned, return as internal error
		return errInternalError
	}
	return nil
}

type handleFunc func(peer transport.Peer, envelope *Envelope) error

func handleASync(peer transport.Peer, envelope *Envelope, f handleFunc) error {
	go func() {
		if err := f(peer, envelope); err != nil {
			log.Logger().Errorf("Error handling %T (peer=%s): %s", envelope.Message, peer, err)
		}
	}()
	return nil
}

func (p *protocol) handle(peer transport.Peer, envelope *Envelope) error {
	switch envelope.Message.(type) {
	case *Envelope_Gossip:
		return handleASync(peer, envelope, p.handleGossip)
	case *Envelope_Hello:
		log.Logger().Infof("%T: %s said hello", p, peer)
		return nil
	case *Envelope_TransactionList:
		// in order handling of transactionLists
		pe := peerEnvelope{
			envelope: envelope,
			peer:     peer,
		}
		select {
		case p.listHandler.ch <- pe:
			// add to channel for processing
		default:
			// when 100 lists are waiting to be processed
			log.Logger().Warnf("Can't handle TransactionList message from %s: channel full", peer)
		}

		return nil
	case *Envelope_TransactionListQuery:
		return handleASync(peer, envelope, p.handleTransactionListQuery)
	case *Envelope_TransactionPayloadQuery:
		return handleASync(peer, envelope, p.handleTransactionPayloadQuery)
	case *Envelope_TransactionPayload:
		return handleASync(peer, envelope, p.handleTransactionPayload)
	case *Envelope_TransactionRangeQuery:
		return handleASync(peer, envelope, p.handleTransactionRangeQuery)
	case *Envelope_State:
		return handleASync(peer, envelope, p.handleState)
	case *Envelope_TransactionSet:
		return handleASync(peer, envelope, p.handleTransactionSet)
	case *Envelope_DiagnosticsBroadcast:
		return handleASync(peer, envelope, p.handleDiagnostics)
	}
	return errMessageNotSupported
}

func (p *protocol) handleTransactionPayloadQuery(peer transport.Peer, envelope *Envelope) error {
	msg := envelope.GetTransactionPayloadQuery()
	ctx := context.Background()

	log.Logger().Tracef("handling TransactionPayloadQuery from peer (peer=%s, conversationID=%s, payload=%s)", peer.ID.String(), msg.ConversationID, msg.TransactionRef)

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

func (p *protocol) handleTransactionPayload(peer transport.Peer, envelope *Envelope) error {
	msg := envelope.GetTransactionPayload()
	ctx := context.Background()
	ref := hash.FromSlice(msg.TransactionRef)

	log.Logger().Tracef("handling TransactionPayload from peer (peer=%s, conversationID=%s, payload=%s)", peer.ID.String(), msg.ConversationID, ref)

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
	if err = p.state.WritePayload(ctx, tx, payloadHash, msg.Data); err != nil {
		return err
	}

	// it's saved, remove the job
	return p.payloadScheduler.Finished(ref)
}

func (p *protocol) handleTransactionRangeQuery(peer transport.Peer, envelope *Envelope) error {
	msg := envelope.GetTransactionRangeQuery()

	log.Logger().Tracef("handling TransactionRangeQuery from peer (peer=%s, conversationID=%s)", peer.ID.String(), msg.ConversationID)

	if msg.Start >= msg.End {
		return errors.New("invalid range query")
	}

	ctx := context.Background()
	txs, err := p.state.FindBetweenLC(ctx, msg.Start, msg.End)
	if err != nil {
		return err
	}

	transactionList, err := p.collectTransactionList(ctx, txs)
	if err != nil {
		return err
	}

	return p.sender.sendTransactionList(peer.ID, conversationID(msg.ConversationID), transactionList)
}

func (p *protocol) handleGossip(peer transport.Peer, envelope *Envelope) error {
	msg := envelope.GetGossip()
	ctx := context.Background()

	log.Logger().Tracef("handling Gossip from peer (peer=%s)", peer.ID.String())

	xor, clock := p.state.XOR(ctx, math.MaxUint32)
	peerXor := hash.FromSlice(msg.XOR)
	if xor.Equals(peerXor) {
		return nil
	}

	//
	refs := make([]hash.SHA256Hash, len(msg.Transactions))
	for i, bytes := range msg.Transactions {
		refs[i] = hash.FromSlice(bytes)
	}
	if len(refs) > 0 {
		p.gManager.GossipReceived(peer.ID, refs...)
	}

	// filter for unknown transactions
	i := 0
	for _, ref := range refs {
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
	log.Logger().Debugf("received %d new transaction references via Gossip from peer=%s", len(refs), peer.ID)

	// request missing refs
	// If our DAG is just missing the TXs from the gossip to get in sync with the peer's DAG, send TransactionListQuery.
	// Test this by XORing the TX refs from the gossip message with our DAG's XOR (should then equal peer DAG's XOR).
	// If the XORs are not equal and the peer is behind, still request the missing refs if there are any.
	tempXor := xor.Xor(refs...)
	if tempXor.Equals(peerXor) || (msg.LC < clock && len(refs) > 0) {
		return p.sender.sendTransactionListQuery(peer.ID, refs)
	}

	// send State if node is missing more refs than referenced in this Gossip
	if len(refs) == 0 {
		log.Logger().Debugf("xor is different from peer=%s but Gossip contained no new transactions", peer.ID)
	} else {
		log.Logger().Debugf("xor is different from peer=%s and peers clock is equal or higher", peer.ID)
	}
	return p.sender.sendState(peer.ID, xor, clock)
}

func (p *protocol) handleTransactionListQuery(peer transport.Peer, envelope *Envelope) error {
	msg := envelope.GetTransactionListQuery()
	requestedRefs := make([]hash.SHA256Hash, len(msg.Refs))
	unsorted := make([]dag.Transaction, 0)

	cid := conversationID(msg.ConversationID)

	log.Logger().Tracef("handling TransactionListQuery from peer (peer=%s, conversationID=%s)", peer.ID.String(), cid.String())

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

	txs, err := p.collectTransactionList(ctx, unsorted)
	if err != nil {
		return err
	}

	return p.sender.sendTransactionList(peer.ID, cid, txs)
}

func (p *protocol) collectTransactionList(ctx context.Context, txs []dag.Transaction) ([]*Transaction, error) {
	var result []*Transaction
	for _, transaction := range txs {
		networkTX := Transaction{
			Data: transaction.Data(),
		}

		// do not add private TX payloads
		if len(transaction.PAL()) == 0 {
			payload, err := p.state.ReadPayload(ctx, transaction.PayloadHash())
			if err != nil {
				return nil, err
			}
			if payload == nil {
				return nil, fmt.Errorf("transaction is missing payload (ref=%s)", transaction.Ref())
			}
			networkTX.Payload = payload
		}
		result = append(result, &networkTX)
	}

	return result, nil
}

func (p *protocol) handleState(peer transport.Peer, envelope *Envelope) error {
	msg := envelope.GetState()
	cid := conversationID(msg.ConversationID)

	log.Logger().Tracef("handling State from peer (peer=%s, conversationID=%s)", peer.ID.String(), cid.String())

	ctx := context.Background()
	xor, lc := p.state.XOR(ctx, math.MaxUint32)

	// nothing to do if peers are now synced
	if xor.Equals(hash.FromSlice(msg.XOR)) {
		return nil
	}

	iblt, _ := p.state.IBLT(ctx, msg.LC)

	return p.sender.sendTransactionSet(peer.ID, cid, msg.LC, lc, iblt)
}

func (p *protocol) handleTransactionSet(peer transport.Peer, envelope *Envelope) error {
	subEnvelope := envelope.Message.(*Envelope_TransactionSet)
	msg := envelope.GetTransactionSet()
	cid := conversationID(msg.ConversationID)
	data := handlerData{}

	log.Logger().Tracef("handling TransactionSet from peer (peer=%s, conversationID=%s)", peer.ID.String(), cid.String())

	// check if response matches earlier request
	if _, err := p.cMan.check(subEnvelope, data); err != nil {
		return err
	}

	// mark state request as done
	p.cMan.done(cid)

	// parse msg data
	minLC := msg.LCReq
	if msg.LC < minLC {
		// peers DAG might be behind. IBLTs cannot be decoded if their range difference is too large.
		minLC = msg.LC
	}
	peerIblt := tree.NewIblt(dag.IbltNumBuckets)
	err := peerIblt.UnmarshalBinary(msg.IBLT)
	if err != nil {
		return err
	}

	// get iblt difference
	ctx := context.Background()
	iblt, _ := p.state.IBLT(ctx, minLC)
	err = iblt.Subtract(peerIblt)
	if err != nil {
		return err
	}

	// Decode iblt
	_, missing, err := iblt.Decode()
	if err != nil {
		if errors.Is(err, tree.ErrDecodeNotPossible) {
			log.Logger().Debugf("peer IBLT decode failed (peer=%s, conversationID=%s)", peer.ID.String(), cid.String())

			// request fist page if decode of first page fails
			if minLC < dag.PageSize {
				return p.sender.sendTransactionRangeQuery(peer.ID, 0, dag.PageSize)
			}
			// send new state message, request one page lower than the current evaluation
			previousPageLimit := pageClockStart(clockToPageNum(minLC)) - 1
			xor, _ := p.state.XOR(ctx, math.MaxUint32)

			log.Logger().Debugf("requesting state of previous page (peer=%s, conversationID=%s)", peer.ID.String(), cid.String())
			return p.sender.sendState(peer.ID, xor, previousPageLimit)
		}
		return err
	}

	// request missing decoded transactions
	if len(missing) > 0 {
		log.Logger().Debugf("peer IBLT decode succesful, requesting %d transactions", len(missing))
		return p.sender.sendTransactionListQuery(peer.ID, missing)
	}

	// request next page(s) if peer's DAG has more pages
	_, localLC := p.state.XOR(ctx, math.MaxUint32)
	peerPageNum, localPageNum, reqPageNum := clockToPageNum(msg.LC), clockToPageNum(localLC), clockToPageNum(msg.LCReq)
	if peerPageNum > reqPageNum {
		log.Logger().Debugf("peer has higher LC values, requesting transactions by range (%d<%d)", reqPageNum, peerPageNum)

		if localPageNum > reqPageNum {
			// only ask for next page when reconciling historical pages
			return p.sender.sendTransactionRangeQuery(peer.ID, pageClockStart(reqPageNum+1), pageClockStart(reqPageNum+2))
		}
		// TODO: Distribute synchronization of new nodes over multiple peers.
		return p.sender.sendTransactionRangeQuery(peer.ID, pageClockStart(reqPageNum+1), math.MaxUint32)
	}

	// peer is behind
	return nil
}

func (p *protocol) handleDiagnostics(peer transport.Peer, envelope *Envelope) error {
	msg := envelope.GetDiagnosticsBroadcast()
	p.diagnosticsMan.handleReceived(peer.ID, msg)
	return nil
}

func pageClockStart(pageNum uint32) uint32 {
	return pageNum * dag.PageSize
}

func clockToPageNum(clock uint32) uint32 {
	return clock / dag.PageSize
}
