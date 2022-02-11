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
	"errors"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/nuts-foundation/nuts-node/network/transport/grpc"
)

func (p *protocol) sendGossipMsg(id transport.PeerID, refs []hash.SHA256Hash) error {
	conn := p.connectionList.Get(grpc.ByConnected(), grpc.ByPeerID(id))
	if conn == nil {
		// shouldn't happen
		return errors.New("no connection available")
	}

	// there shouldn't be more than a 100 in there, this will fit in a message
	refsAsBytes := make([][]byte, len(refs))
	for i, ref := range refs {
		refsAsBytes[i] = ref.Slice()
	}

	return conn.Send(p, &Envelope{Message: &Envelope_Gossip{
		Gossip: &Gossip{
			Transactions: refsAsBytes,
		},
	}})
}
