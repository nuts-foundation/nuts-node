package grpc

import (
	"github.com/nuts-foundation/nuts-node/network/transport"
	"sync"
)

type connectionList struct {
	mux  sync.Mutex
	list []managedConnection
}

func (c *connectionList) closeAll() {
	c.mux.Lock()
	defer c.mux.Unlock()

	for _, curr := range c.list {
		curr.close()
	}
}

// getOrRegister retrieves the connection that matches the given peer (either on ID or address).
// If no connections match the given peer it creates a new one.
// It returns false if the peer matched an existing connection.
// It returns true if a new connection was created.
func (c *connectionList) getOrRegister(peer transport.Peer, dialer dialer) (managedConnection, bool) {
	c.mux.Lock()
	defer c.mux.Unlock()

	// Check whether we're already connected to this peer
	for _, curr := range c.list {
		// This works for both outbound and inbound
		currPeer := curr.getPeer()
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

func (c *connectionList) connected(peer transport.Peer) bool {
	c.mux.Lock()
	defer c.mux.Unlock()

	for _, curr := range c.list {
		currPeer := curr.getPeer()
		if len(currPeer.ID) > 0 && currPeer.ID == peer.ID || len(currPeer.Address) > 0 && currPeer.Address == peer.Address {
			return curr.connected()
		}
	}
	return false
}

func (c *connectionList) listConnected() []transport.Peer {
	c.mux.Lock()
	defer c.mux.Unlock()

	var result []transport.Peer
	for _, curr := range c.list {
		if curr.connected() {
			result = append(result, curr.getPeer())
		}
	}
	return result
}
