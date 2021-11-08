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

// ConnectionManager manages the connections to peers, making outbound connections if required. It also determines the network layout.
type ConnectionManager interface {
	// Connect attempts to make an outbound connection to the given peer if it's not already connected.
	Connect(peerAddress string)

	// Peers returns a slice containing the peers that are currently connected.
	Peers() []Peer

	// Start instructs the ConnectionManager to start accepting connections and prepare to make outbound connections.
	Start() error

	// Stop shuts down the connections made by the ConnectionManager.
	Stop()
}
