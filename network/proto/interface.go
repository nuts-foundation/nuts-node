/*
 * Copyright (C) 2020. Nuts community
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
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/network/p2p"
	"time"
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
	Configure(p2pNetwork p2p.P2PNetwork, graph dag.DAG, payloadStore dag.PayloadStore, advertHashesInterval time.Duration, peerID p2p.PeerID)
	// Starts the Protocol (sending and receiving of messages).
	Start()
	// Stops the Protocol.
	Stop()
}

// PeerHashQueue is a queue which contains the hashes adverted by our peers. It's a FILO queue, since
// the hashes represent append-only data structures which means the last one is most recent.
type PeerHashQueue interface {
	// Get blocks until there's an PeerHash available and returns it.
	Get() *PeerHash
}

// PeerHash describes a hash we received from a peer.
type PeerHash struct {
	// Peer holds the ID of the peer we got the hash from.
	Peer p2p.PeerID
	// Hashes holds the hashes we received.
	Hashes []hash.SHA256Hash
}

type chanPeerHashQueue struct {
	c chan *PeerHash
}

func (q chanPeerHashQueue) Get() *PeerHash {
	return <-q.c
}
