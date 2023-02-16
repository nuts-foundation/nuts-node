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

package transport

import (
	"github.com/nuts-foundation/nuts-node/core"
)

// ConnectionOption is the option function for adding options when establishing a connection through the connection manager.
// The options are set on the Peer
type ConnectionOption func(peer *Peer)

// WithUnauthenticated is the option for allowing the connection to be unauthenticated.
// The node.DID authentication on a connection will always succeed. Actions that require the node.DID will fail.
func WithUnauthenticated() ConnectionOption {
	return func(peer *Peer) {
		peer.AcceptUnauthenticated = true
	}
}

// StreamStateObserverFunc is a function that can be registered on the connection manager.
// If a stream state changes this callback will be called. It's called per protocol.
type StreamStateObserverFunc func(peer Peer, state StreamState, protocol Protocol)

// StreamState is a type for defining connection states
type StreamState string

const (
	// StateConnected is passed to the connection observers when a stream state changed to connected
	StateConnected StreamState = "connected"
	// StateDisconnected is passed to the connection observers when a stream state changed to disconnected
	StateDisconnected StreamState = "disconnected"
)

// ConnectionManager manages the connections to peers, making outbound connections if required. It also determines the network layout.
type ConnectionManager interface {
	core.Diagnosable

	// Connect attempts to make an outbound connection to the given peer if it's not already connected.
	// acceptNonAuthenticated indicates if the connection must be kept even if the other end can't be authenticated.
	// The connection can then still be used for non-authenticated purposes.
	Connect(peerAddress string, option ...ConnectionOption)

	// Peers returns a slice containing the peers that are currently connected.
	Peers() []Peer

	// RegisterObserver allows to register a callback function for stream state changes
	RegisterObserver(callback StreamStateObserverFunc)

	// Start instructs the ConnectionManager to start accepting connections and prepare to make outbound connections.
	Start() error

	// Stop shuts down the connections made by the ConnectionManager.
	Stop()
}
