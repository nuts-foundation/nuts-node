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
	"context"
	"errors"
	"sync"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/network/transport"
)

// ErrNoConnection can be used when no connectin is available but one is required.
var ErrNoConnection = errors.New("no connection available")

// ConnectionList provides an API for protocols to query the ConnectionManager's connections.
type ConnectionList interface {
	// Get returns the first Connection which matches the predicates (using AND)
	// If there's no match, nil is returned.
	Get(query ...Predicate) Connection
	// All returns the list of connections.
	All() []Connection
	// AllMatching returns the list of connections which match the predicates (using AND).
	AllMatching(query ...Predicate) []Connection
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
// The given context is used as parent context for new connections: if it's cancelled, callers blocked by waitUntilDisconnected will be unblocked.
func (c *connectionList) getOrRegister(ctx context.Context, peer transport.Peer, dialer dialer, outbound bool) (Connection, bool) {
	c.mux.Lock()
	defer c.mux.Unlock()

	// Check whether we're already connected to this peer
	for _, curr := range c.list {
		// This works for both outbound and inbound
		currPeer := curr.Peer()
		if len(peer.ID) > 0 && currPeer.ID == peer.ID {
			return curr, false
		}
		if outbound {
			if len(peer.Address) > 0 && peer.Address == currPeer.Address {
				return curr, false
			}
		}
	}

	result := createConnection(ctx, dialer, peer)
	c.list = append(c.list, result)
	return result, true
}

func (c *connectionList) All() []Connection {
	c.mux.Lock()
	defer c.mux.Unlock()

	result := make([]Connection, len(c.list))
	copy(result, c.list)
	return result
}

func (c *connectionList) AllMatching(query ...Predicate) []Connection {
	c.mux.Lock()
	defer c.mux.Unlock()

	var result []Connection
outer:
	for _, curr := range c.list {
		for _, predicate := range query {
			if !predicate.Match(curr) {
				continue outer
			}
		}

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
	// Only add peer to "outbound_connectors" list if not connected
	for _, curr := range c.list {
		if curr.IsConnected() {
			peers = append(peers, curr.Peer())
		} else {
			connector := curr.outboundConnector()
			if connector != nil {
				connectors = append(connectors, connector.stats())
			}
		}
	}
	return []core.DiagnosticResult{
		numberOfPeersStatistic{numberOfPeers: len(peers)},
		peersStatistic{peers: peers},
		connectors,
	}
}
