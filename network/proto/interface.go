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
	Configure(p2pNetwork p2p.Adapter, graph dag.DAG, publisher dag.Publisher, payloadStore dag.PayloadStore, diagnosticsProvider func() Diagnostics,
		advertHashesInterval time.Duration, advertDiagnosticsInterval time.Duration, peerID p2p.PeerID)
	// Starts the Protocol (sending and receiving of messages).
	Start()
	// Stops the Protocol.
	Stop()
	// PeerDiagnostics returns a map containing diagnostic information of the node's peers. The key contains the remote peer's ID.
	PeerDiagnostics() map[p2p.PeerID]Diagnostics
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

// Diagnostics contains information that is shared to this node's peers on request.
type Diagnostics struct {
	// Uptime the uptime (time since the node started) in seconds.
	Uptime time.Duration `json:"uptime"`
	// Peers contains the peer IDs of the node's peers.
	Peers []p2p.PeerID `json:"peers"`
	// NumberOfTransactions contains the total number of transactions on the node's DAG.
	NumberOfTransactions uint32 `json:"transactionNum"`
	// SoftwareVersion contains an indication of the software version of the node. It's recommended to use a (Git) commit ID that uniquely resolves to a code revision, alternatively a semantic version could be used (e.g. 1.2.5).
	SoftwareVersion string `json:"softwareVersion"`
	// SoftwareID contains an indication of the vendor of the software of the node. For open source implementations it's recommended to specify URL to the public, open source repository.
	// Proprietary implementations could specify the product's or vendor's name.
	SoftwareID string `json:"softwareID"`
}
