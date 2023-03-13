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

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/network/transport/grpc"
)

// connectionEnvelope is a structure to communicate both the message and the peer over a channel
type connectionEnvelope struct {
	connection grpc.Connection
	envelope   *Envelope
}

// transactionListHandler is a small helper to start a routine for handling TransactionList message over a channel
// The messages are handled one at a time to prevent concurrent locking on the DB
type transactionListHandler struct {
	ctx context.Context
	ch  chan connectionEnvelope
	fn  handleFunc
}

// newTransactionListHandler creates a new transactionListHandler.
// The passed context is used to stop the go routine when cancelled.
func newTransactionListHandler(ctx context.Context, fn handleFunc) *transactionListHandler {
	// limit must be the same as outbound limit
	ch := make(chan connectionEnvelope, grpc.OutboxHardLimit)

	return &transactionListHandler{
		ctx: ctx,
		ch:  ch,
		fn:  fn,
	}
}

func (tlh *transactionListHandler) start() {
	for {
		select {
		case <-tlh.ctx.Done():
			return
		case pe := <-tlh.ch:
			if err := tlh.fn(tlh.ctx, pe.connection, pe.envelope); err != nil {
				log.Logger().
					WithError(err).
					WithFields(pe.connection.Peer().ToFields()).
					WithField(core.LogFieldMessageType, fmt.Sprintf("%T", pe.envelope.Message)).
					Error("Error handling message")
			}
		}
	}
}

func (p *protocol) handleTransactionList(ctx context.Context, connection grpc.Connection, envelope *Envelope) error {
	subEnvelope := envelope.Message.(*Envelope_TransactionList)
	msg := envelope.GetTransactionList()
	cid := conversationID(msg.ConversationID)
	data := handlerData{}

	log.Logger().
		WithFields(connection.Peer().ToFields()).
		WithField(core.LogFieldConversationID, cid).
		Tracef("Handling handleTransactionList from peer (message=%d/%d)", msg.MessageNumber, msg.TotalMessages)

	// check if response matches earlier request
	if _, err := p.cMan.check(subEnvelope, data); err != nil {
		return err
	}

	txs, err := subEnvelope.parseTransactions(data)
	if err != nil {
		return err
	}

	for i, tx := range txs {
		if ctx.Err() != nil {
			// For loop might be long-running, support cancellation
			break
		}
		// TODO does this always trigger fetching missing payloads? (through observer on DAG) Prolly not for v2
		if len(tx.PAL()) == 0 && len(msg.Transactions[i].Payload) == 0 {
			return fmt.Errorf("peer did not provide payload for transaction (tx=%s)", tx.Ref())
		}
		if err = p.state.Add(ctx, tx, msg.Transactions[i].Payload); err != nil {
			if errors.Is(err, dag.ErrPreviousTransactionMissing) {
				p.cMan.done(cid)
				log.Logger().
					WithFields(connection.Peer().ToFields()).
					WithField(core.LogFieldConversationID, cid).
					WithField(core.LogFieldTransactionRef, tx.Ref()).
					Warn("Ignoring remainder of TransactionList due to missing prevs")
				xor, clock := p.state.XOR(dag.MaxLamportClock)
				return p.sender.sendState(connection, xor, clock)
			}
			return fmt.Errorf("unable to add received transaction to DAG (tx=%s): %w", tx.Ref(), err)
		}
	}

	if msg.MessageNumber >= msg.TotalMessages {
		p.cMan.done(cid)
	} else {
		p.cMan.resetTimeout(cid)
	}

	return nil
}
