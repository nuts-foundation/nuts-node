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
	"fmt"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/network/transport"
)

// P2PNetwork defines the API for the P2P layer, used to connect to peers and exchange messages.
type P2PNetwork interface {
	core.Diagnosable
	// Configure configures the P2PNetwork. Must be called before Start().
	Configure(config P2PNetworkConfig) error
	// Configured returns whether the system is configured or not
	Configured() bool
	// Start starts the P2P network on the local node.
	Start() error
	// Stop stops the P2P network on the local node.
	Stop() error
	// AddRemoteNode adds a remote node to the local node's view of the network, so it can become one of our peers.
	// If we'll try to connect to the remote node, true is returned, otherwise false.
	ConnectToPeer(address string) bool
	// ReceivedMessages returns a queue containing all messages received from our peers. It must be drained, because when its buffer is full the producer (P2PNetwork) is blocked.
	ReceivedMessages() MessageQueue
	// Send sends a message to a specific peer.
	Send(peer PeerID, message *transport.NetworkMessage) error
	// Broadcast sends a message to all peers.
	Broadcast(message *transport.NetworkMessage)
	// Peers returns our peers (remote nodes we're currently connected to).
	Peers() []Peer
}

type MessageQueue interface {
	Get() PeerMessage
}

// Peer holds the properties of a remote node we're connected to
type Peer struct {
	// ID holds the unique identificator of the peer
	ID PeerID
	// Address holds the remote address of the node we're actually connected to
	Address string
}

func (p Peer) String() string {
	return fmt.Sprintf("%s@%s", p.ID, p.Address)
}

type PeerID string

func (p PeerID) String() string {
	return string(p)
}

type PeerMessage struct {
	Peer    PeerID
	Message *transport.NetworkMessage
}

type P2PNetworkConfig struct {
	PeerID PeerID
	// ListenAddress specifies the socket address the gRPC server should listen on.
	// If not set, the node will not accept incoming connections (but outbound connections can still be made).
	ListenAddress  string
	BootstrapNodes []string
	ClientCert     tls.Certificate
	// ServerCert specifies the TLS server certificate. If set the server should open a TLS socket, otherwise plain TCP.
	ServerCert tls.Certificate
	TrustStore *x509.CertPool
}

func (cfg P2PNetworkConfig) tlsEnabled() bool {
	return cfg.TrustStore != nil
}
