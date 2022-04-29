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
	"context"
	"errors"
	"fmt"
	"math"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/network/transport"
)

// peerEnvelope is a structure to communicate both the message and the peer over a channel
type peerEnvelope struct {
	peer     transport.Peer
	envelope *Envelope
}

// transactionListHandler is a small helper to start a routine for handling TransactionList message over a channel
// The messages are handled one at a time to prevent concurrent locking on the DB
type transactionListHandler struct {
	ctx context.Context
	ch  chan peerEnvelope
	fn  handleFunc
}

// newTransactionListHandler creates a new transactionListHandler.
// The passed context is used to stop the go routine when cancelled.
func newTransactionListHandler(ctx context.Context, fn handleFunc) *transactionListHandler {
	ch := make(chan peerEnvelope, 100)

	return &transactionListHandler{
		ctx: ctx,
		ch:  ch,
		fn:  fn,
	}
}

func (tlh *transactionListHandler) start() {
	go func() {
		for {
			select {
			case <-tlh.ctx.Done():
				return
			case pe := <-tlh.ch:
				if err := tlh.fn(pe.peer, pe.envelope); err != nil {
					log.Logger().Errorf("Error handling %T (peer=%s): %s", pe.envelope.Message, pe.peer, err)
				}
			}
		}
	}()
}

func (p *protocol) handleTransactionList(peer transport.Peer, envelope *Envelope) error {
	subEnvelope := envelope.Message.(*Envelope_TransactionList)
	msg := envelope.GetTransactionList()
	cid := conversationID(msg.ConversationID)
	data := handlerData{}

	log.Logger().Tracef("Handling handleTransactionList from peer (peer=%s, conversationID=%s, message=%d/%d)", peer.ID, cid, msg.MessageNumber, msg.TotalMessages)

	// check if response matches earlier request
	if _, err := p.cMan.check(subEnvelope, data); err != nil {
		return err
	}

	txs, err := subEnvelope.parseTransactions(data)
	if err != nil {
		return err
	}

	p.handlerMutex.Lock()
	defer p.handlerMutex.Unlock()

	refsToBeRemoved := map[hash.SHA256Hash]bool{}

	ctx := context.Background()
	maxLC := uint32(0)
	for i, tx := range txs {
		// TODO does this always trigger fetching missing payloads? (through observer on DAG) Prolly not for v2
		if len(tx.PAL()) == 0 && len(msg.Transactions[i].Payload) == 0 {
			return fmt.Errorf("peer did not provide payload for transaction (tx=%s)", tx.Ref())
		}
		if err = p.state.Add(ctx, tx, msg.Transactions[i].Payload); err != nil {
			if errors.Is(err, dag.ErrPreviousTransactionMissing) {
				p.cMan.done(cid)
				log.Logger().Warnf("ignoring remainder of TransactionList due to missing prevs (conversation=%s, Tx with missing prevs=%s)", cid, tx.Ref())
				xor, clock := p.state.XOR(ctx, math.MaxUint32)
				return p.sender.sendState(peer.ID, xor, clock)
			}
			return fmt.Errorf("unable to add received transaction to DAG (tx=%s): %w", tx.Ref(), err)
		}
		if tx.Clock() > maxLC {
			maxLC = tx.Clock()
		}
		refsToBeRemoved[tx.Ref()] = true
	}

	if msg.MessageNumber >= msg.TotalMessages {
		p.cMan.done(cid)
	}

	return nil
}
