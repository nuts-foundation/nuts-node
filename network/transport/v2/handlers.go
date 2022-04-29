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
	"github.com/nuts-foundation/nuts-node/network/dag/tree"
	"math"
	"sort"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag"
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

func (p protocol) Handle(peer transport.Peer, raw interface{}) error {
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

func (p protocol) handle(peer transport.Peer, envelope *Envelope) error {
	switch msg := envelope.Message.(type) {
	case *Envelope_Gossip:
		return p.handleGossip(peer, msg.Gossip)
	case *Envelope_Hello:
		log.Logger().Infof("%T: %s said hello", p, peer)
		return nil
	case *Envelope_TransactionList:
		return p.handleTransactionList(peer, msg)
	case *Envelope_TransactionListQuery:
		return p.handleTransactionListQuery(peer, msg.TransactionListQuery)
	case *Envelope_TransactionPayloadQuery:
		return p.handleTransactionPayloadQuery(peer, msg.TransactionPayloadQuery)
	case *Envelope_TransactionPayload:
		return p.handleTransactionPayload(msg.TransactionPayload)
	case *Envelope_TransactionRangeQuery:
		return p.handleTransactionRangeQuery(peer, msg)
	case *Envelope_State:
		return p.handleState(peer, msg.State)
	case *Envelope_TransactionSet:
		return p.handleTransactionSet(peer, msg)
	case *Envelope_DiagnosticsBroadcast:
		p.handleDiagnostics(peer.ID, msg.DiagnosticsBroadcast)
		return nil
	}
	return errMessageNotSupported
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

func (p protocol) handleTransactionRangeQuery(peer transport.Peer, envelope *Envelope_TransactionRangeQuery) error {
	msg := envelope.TransactionRangeQuery

	if envelope.TransactionRangeQuery.Start >= envelope.TransactionRangeQuery.End {
		return errors.New("invalid range query")
	}

	ctx := context.Background()
	txs, err := p.state.FindBetweenLC(ctx, envelope.TransactionRangeQuery.Start, envelope.TransactionRangeQuery.End)
	if err != nil {
		return err
	}

	transactionList, err := p.collectTransactionList(ctx, txs)
	if err != nil {
		return err
	}

	return p.sender.sendTransactionList(peer.ID, conversationID(msg.ConversationID), transactionList)
}

func (p *protocol) handleGossip(peer transport.Peer, msg *Gossip) error {
	ctx := context.Background()
	xor, clock := p.state.XOR(ctx, math.MaxUint32)
	peerXor := hash.FromSlice(msg.XOR)
	if xor.Equals(peerXor) {
		return nil
	}

	refs := make([]hash.SHA256Hash, len(msg.Transactions))
	i := 0
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
		p.gManager.GossipReceived(peer.ID, refs...)
		err := p.sender.sendTransactionListQuery(peer.ID, refs)
		if err != nil {
			return err
		}
		// querying refs with missing prevs will trigger a State msg
	}

	tempXor := xor.Xor(refs...)
	if msg.LC >= clock && !tempXor.Equals(peerXor) {
		// TODO swap for trace logging
		log.Logger().Infof("xor is different from peer=%s and peers clock is equal or higher", peer.ID)
		return p.sender.sendState(peer.ID, xor, clock)
	}

	// peer is behind
	return nil
}

func (p *protocol) handleTransactionList(peer transport.Peer, envelope *Envelope_TransactionList) error {
	msg := envelope.TransactionList
	cid := conversationID(msg.ConversationID)
	data := handlerData{}

	// TODO convert to trace logging
	log.Logger().Infof("handling handleTransactionList from peer (peer=%s, conversationID=%s)", peer.ID.String(), cid.String())

	// check if response matches earlier request
	var conversation *conversation
	var err error
	if conversation, err = p.cMan.check(envelope, data); err != nil {
		return err
	}

	txs, err := envelope.parseTransactions(data)
	if err != nil {
		return err
	}

	refsToBeRemoved := map[hash.SHA256Hash]bool{}
	ctx := context.Background()
	for i, tx := range txs {
		// TODO does this always trigger fetching missing payloads? (through observer on DAG) Prolly not for v2
		if len(tx.PAL()) == 0 && len(envelope.TransactionList.Transactions[i].Payload) == 0 {
			return fmt.Errorf("peer did not provide payload for transaction (tx=%s)", tx.Ref())
		}
		if err = p.state.Add(ctx, tx, envelope.TransactionList.Transactions[i].Payload); err != nil {
			if errors.Is(err, dag.ErrPreviousTransactionMissing) {
				p.cMan.done(cid)
				log.Logger().Warnf("ignoring remainder of TransactionList due to missing prevs (conversation=%s, Tx with missing prevs=%s)", cid, tx.Ref())
				xor, clock := p.state.XOR(ctx, math.MaxUint32)
				return p.sender.sendState(peer.ID, xor, clock)
			}
			return fmt.Errorf("unable to add received transaction to DAG (tx=%s): %w", tx.Ref(), err)
		}
		refsToBeRemoved[tx.Ref()] = true
	}

	// remove from conversation
	refs := conversation.get("refs")
	if refs != nil {
		requestedRefs := refs.([]hash.SHA256Hash)
		newRefs := make([]hash.SHA256Hash, len(requestedRefs))
		i := 0
		for _, requestedRef := range requestedRefs {
			if _, ok := refsToBeRemoved[requestedRef]; !ok {
				newRefs[i] = requestedRef
				i++
			}
		}
		newRefs = newRefs[:i]
		conversation.set("refs", newRefs)

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

func (p *protocol) handleState(peer transport.Peer, msg *State) error {
	cid := conversationID(msg.ConversationID)

	// TODO convert to trace logging
	log.Logger().Infof("handling State from peer (peer=%s, conversationID=%s)", peer.ID.String(), cid.String())

	ctx := context.Background()
	xor, lc := p.state.XOR(ctx, math.MaxUint32)

	// nothing to do if peers are now synced
	if xor.Equals(hash.FromSlice(msg.XOR)) {
		return nil
	}

	iblt, _ := p.state.IBLT(ctx, msg.LC)

	return p.sender.sendTransactionSet(peer.ID, cid, msg.LC, lc, iblt)
}

func (p *protocol) handleTransactionSet(peer transport.Peer, envelope *Envelope_TransactionSet) error {
	msg := envelope.TransactionSet
	cid := conversationID(msg.ConversationID)
	data := handlerData{}

	// TODO convert to trace logging
	log.Logger().Debugf("handling TransactionSet from peer (peer=%s, conversationID=%s)", peer.ID.String(), cid.String())

	// check if response matches earlier request
	if _, err := p.cMan.check(envelope, data); err != nil {
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

	// request all missing transactions
	if len(missing) > 0 {
		log.Logger().Debugf("peer IBLT decode succesful, requesting %d transactions", len(missing))

		err = p.sender.sendTransactionListQuery(peer.ID, missing)
		if err != nil {
			return err
		}
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

func (p *protocol) handleDiagnostics(peer transport.PeerID, response *Diagnostics) {
	p.diagnosticsMan.handleReceived(peer, response)
}

func pageClockStart(pageNum uint32) uint32 {
	return pageNum * dag.PageSize
}

func clockToPageNum(clock uint32) uint32 {
	return clock / dag.PageSize
}
