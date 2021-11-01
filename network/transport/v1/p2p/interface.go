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

package p2p

import (
	"crypto/tls"
	"crypto/x509"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/nuts-foundation/nuts-node/network/transport/grpc"
	"github.com/nuts-foundation/nuts-node/network/transport/v1/protobuf"
)

// Adapter defines the API for the P2P layer, used to connect to peers and exchange messages.
type Adapter interface {
	grpc.ServiceImplementor
	core.Diagnosable
	// Configure configures the Adapter. Must be called before Start().
	Configure(config AdapterConfig) error
	// Start starts the P2P network on the local node.
	Start() error
	// Stop stops the P2P network on the local node.
	Stop() error
	// ConnectToPeer adds a remote node to the local node's view of the network, so it can become one of our peers.
	// If we'll try to connect to the remote node, true is returned, otherwise false.
	ConnectToPeer(address string) bool
	// ReceivedMessages returns a queue containing all messages received from our peers. It must be drained, because when its buffer is full the producer (Adapter) is blocked.
	ReceivedMessages() MessageQueue
	// Send sends a message to a specific peer.
	Send(peer transport.PeerID, message *protobuf.NetworkMessage) error
	// Broadcast sends a message to all peers.
	Broadcast(message *protobuf.NetworkMessage)
	// Peers returns our peers (remote nodes we're currently connected to).
	Peers() []transport.Peer
	// EventChannels returns the channels that are used to communicate P2P network events on. They MUST be listened
	// on by a consumer.
	EventChannels() (peerConnected chan transport.Peer, peerDisconnected chan transport.Peer)
}

// MessageQueue defines an interfaces for reading incoming network messages from a queue.
type MessageQueue interface {
	// Get returns the next message from the queue, blocking until a message is available. When the queue is shutdown
	// it returns nil.
	Get() PeerMessage
}

// PeerMessage defines a message received from a peer.
type PeerMessage struct {
	// Peer identifies who sent the message.
	Peer transport.PeerID
	// Message contains the received message.
	Message *protobuf.NetworkMessage
}

// AdapterConfig contains configuration for the P2P adapter.
type AdapterConfig struct {
	// PeerID contains the ID of the local node.
	PeerID transport.PeerID
	// ServerCert specifies the TLS client certificate. If set the client should open a TLS socket, otherwise plain TCP.
	ClientCert tls.Certificate
	// TrustStore contains the trust anchors used when verifying remote a peer's TLS certificate.
	TrustStore    *x509.CertPool
	ListenAddress string
}

func (cfg AdapterConfig) tlsEnabled() bool {
	return cfg.TrustStore != nil
}
