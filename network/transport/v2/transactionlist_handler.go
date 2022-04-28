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

	"github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/network/transport"
)

type peerEnvelope struct {
	peer     transport.Peer
	envelope *Envelope
}

type transactionListHandler struct {
	ctx context.Context
	ch  chan peerEnvelope
	fn  handleFunc
}

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
					log.Logger().Errorf("error handling %T (peer=%s): %s", pe.envelope.Message, pe.peer, err)
				}
			}
		}
	}()
}
