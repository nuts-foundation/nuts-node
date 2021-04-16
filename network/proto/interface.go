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
	Configure(p2pNetwork p2p.P2PNetwork, graph dag.DAG, publisher dag.Publisher, payloadStore dag.PayloadStore, verifier dag.TransactionSignatureVerifier, advertHashesInterval time.Duration, peerID p2p.PeerID)
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

// DAGBlocks defines the API for algorithms that determine the head transactions for DAG blocks.
type DAGBlocks interface {
	// String returns the state of the algorithm as string.
	String() string
	// Heads returns a slice containing the DAG blocks left-to-right (historic block at [0], current block at [len(blocks) - 1]).
	Get() []DAGBlock
	// AddTransaction adds a transaction to the DAG blocks structure. It MUST be called in actual transactions order,
	// So given TXs `A <- B <- [C, D]` call order is A, B, C, D (or A, B, D, C).
	// It will typically be called using a sequential DAG subscriber.
	AddTransaction(tx dag.SubscriberTransaction, _ []byte) error
}

// DAGBlock is a DAG block.
type DAGBlock struct {
	// Start contains the start time of the block.
	Start time.Time
	// Heads contains the heads of the block.
	Heads []hash.SHA256Hash
}
