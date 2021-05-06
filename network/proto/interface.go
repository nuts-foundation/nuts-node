/*
 * Copyright (C) 2021 Nuts community
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

package proto

import (
	"errors"
	"time"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/network/p2p"
)

// Version holds the number of the version of this protocol implementation.
const Version = 1

// ErrMissingProtocolVersion is used when a message is received without protocol version.
var ErrMissingProtocolVersion = errors.New("missing protocol version")

// ErrUnsupportedProtocolVersion is used when a message is received with an unsupported protocol version.
var ErrUnsupportedProtocolVersion = errors.New("unsupported protocol version")

// Protocol defines the API for the protocol layer, which is a high-level interface to interact with the network. It responds
// from (peer) messages received through the P2P layer.
type Protocol interface {
	core.Diagnosable
	// Configure configures the Protocol. Must be called before Start().
	Configure(p2pNetwork p2p.Adapter, graph dag.DAG, publisher dag.Publisher, payloadStore dag.PayloadStore, advertHashesInterval time.Duration, peerID p2p.PeerID)
	// Starts the Protocol (sending and receiving of messages).
	Start()
	// Stops the Protocol.
	Stop()
}

// PeerOmnihashQueue is a queue which contains the omnihashes (DAG reduced to a single hash) from our peers.
type PeerOmnihashQueue interface {
	// Get blocks until there's an PeerOmnihash available and returns it.
	Get() *PeerOmnihash
}

// PeerOmnihash describes a peer and its DAG reduced to a single hash.
type PeerOmnihash struct {
	// Peer holds the ID of the peer we got the hash from.
	Peer p2p.PeerID
	// Hash holds the actual hash.
	Hash hash.SHA256Hash
}
