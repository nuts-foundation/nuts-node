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
	"time"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/core"
)

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

	// Connect attempts to make an outbound connection to the given peer, after the delay has expired.
	// If the delay is 0 it will immediately start connecting. It will take the existing backoff into account when it is nil.
	Connect(peerAddress string, peerDID did.DID, delay *time.Duration)

	// Peers returns a slice containing the peers that are currently connected.
	Peers() []Peer

	// RegisterObserver allows to register a callback function for stream state changes
	RegisterObserver(callback StreamStateObserverFunc)

	// Start instructs the ConnectionManager to start accepting connections and prepare to make outbound connections.
	Start() error

	// Stop shuts down the connections made by the ConnectionManager.
	Stop()
}
