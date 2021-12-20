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

// ConnectionList provides an API for protocols to query the ConnectionManager's connections.
type ConnectionList interface {
	// Get returns the first Connection which matches the predicate
	// If there's no match, nil is returned.
	Get(query ...Predicate) Connection
	// All returns the list of connections.
	All() []Connection
}

type connectionList struct {
	mux  sync.Mutex
	list []Connection
}

func (c *connectionList) Get(query ...Predicate) Connection {
	// Make sure we're not returning the first random connection by accident
	if len(query) == 0 {
		return nil
	}

	c.mux.Lock()
	defer c.mux.Unlock()

outer:
	for _, curr := range c.list {
		for _, predicate := range query {
			if !predicate.Match(curr) {
				continue outer
			}
		}

		return curr
	}

	return nil
}

func (c *connectionList) forEach(consumer func(connection Connection)) {
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

func (c *connectionList) All() []Connection {
	c.mux.Lock()
	defer c.mux.Unlock()

	var result []Connection
	for _, curr := range c.list {
		result = append(result, curr)
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
	defer c.mux.Unlock()
	var peers []transport.Peer
	for _, curr := range c.list {
		connectors = append(connectors, curr.stats())
		if curr.Connected() {
			peers = append(peers, curr.Peer())
		}
	}
	return []core.DiagnosticResult{
		numberOfPeersStatistic{numberOfPeers: len(peers)},
		peersStatistic{peers: peers},
		connectors,
	}
}
