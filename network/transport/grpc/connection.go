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
	"github.com/nuts-foundation/nuts-node/network/transport"
	"sync"
)

type managedConnection struct {
	peer    transport.Peer
	closers []chan struct{}
	mux     sync.Mutex
}

func (mc *managedConnection) closer() chan struct{} {
	mc.mux.Lock()
	defer mc.mux.Unlock()
	closer := make(chan struct{}, 1)
	mc.closers = append(mc.closers, closer)
	return closer
}

func (mc *managedConnection) close() {
	mc.mux.Lock()
	defer mc.mux.Unlock()

	for _, closer := range mc.closers {
		if len(closer) == 0 { // make sure we don't block should this function be called twice
			closer <- struct{}{}
		}
	}
}

type connectionList struct {
	mux  sync.Mutex
	list []*managedConnection
}

func (c *connectionList) closeAll() {
	c.mux.Lock()
	defer c.mux.Unlock()

	for _, curr := range c.list {
		curr.close()
	}
}

func (c *connectionList) getOrRegister(peer transport.Peer) *managedConnection {
	c.mux.Lock()
	defer c.mux.Unlock()

	// Check whether we're already connected to this peer (by ID)
	for _, curr := range c.list {
		if curr.peer.ID == peer.ID {
			return curr
		}
	}

	result := &managedConnection{peer: peer}
	c.list = append(c.list, result)
	return result
}

func (c *connectionList) connected(peerID transport.PeerID) bool {
	c.mux.Lock()
	defer c.mux.Unlock()

	for _, curr := range c.list {
		if curr.peer.ID == peerID {
			return true
		}
	}

	return false
}
