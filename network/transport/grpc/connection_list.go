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

package grpc

import (
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"sync"
)

type ConnectionList interface {
	Get(peer transport.PeerID) Connection
	ForEach(consumer func(connection Connection))
}

type connectionList struct {
	mux  sync.Mutex
	list []Connection
}

func (c *connectionList) Get(peer transport.PeerID) Connection {
	if len(peer.String()) == 0 {
		return nil
	}

	c.mux.Lock()
	defer c.mux.Unlock()

	for _, curr := range c.list {
		if curr.Peer().ID == peer {
			return curr
		}
	}

	return nil
}

func (c *connectionList) ForEach(consumer func(connection Connection)) {
	c.mux.Lock()
	defer c.mux.Unlock()

	for _, curr := range c.list {
		consumer(curr)
	}
}

// getOrRegister retrieves the connection that matches the given peer (either on ID or address).
// If no connections match the given peer it creates a new one.
// It returns false if the peer matched an existing connection.
// It returns true if a new connection was created.
func (c *connectionList) getOrRegister(peer transport.Peer, dialer dialer) (Connection, bool) {
	c.mux.Lock()
	defer c.mux.Unlock()

	// Check whether we're already connected to this peer
	for _, curr := range c.list {
		// This works for both outbound and inbound
		currPeer := curr.Peer()
		if len(peer.ID) > 0 && currPeer.ID == peer.ID {
			return curr, false
		}
		// This works only for outbound
		if len(peer.Address) > 0 && peer.Address == currPeer.Address {
			return curr, false
		}
	}

	result := createConnection(dialer, peer)
	c.list = append(c.list, result)
	return result, true
}

func (c *connectionList) listConnected() []transport.Peer {
	c.mux.Lock()
	defer c.mux.Unlock()

	var result []transport.Peer
	for _, curr := range c.list {
		if curr.Connected() {
			result = append(result, curr.Peer())
		}
	}
	return result
}

func (c *connectionList) remove(target Connection) {
	c.mux.Lock()
	defer c.mux.Unlock()

	var j int
	for _, curr := range c.list {
		if curr != target {
			c.list[j] = curr
			j++
		}
	}
	c.list = c.list[:j]
}

func (c *connectionList) Diagnostics() []core.DiagnosticResult {
	var connectors ConnectorsStats
	c.mux.Lock()
	for _, curr := range c.list {
		connectors = append(connectors, curr.stats())
	}
	c.mux.Unlock()

	peers := c.listConnected()
	return []core.DiagnosticResult{
		numberOfPeersStatistic{numberOfPeers: len(peers)},
		peersStatistic{peers: peers},
		connectors,
	}
}
