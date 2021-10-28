package grpc

import (
	"github.com/nuts-foundation/nuts-node/network/transport"
	"sync"
)

type managedConnection struct {
	peer    transport.Peer
	closers []chan struct{}
	mux     *sync.Mutex
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
	mux  *sync.Mutex
	list []*managedConnection
}

func (c *connectionList) closeAll() {
	c.mux.Lock()
	defer c.mux.Unlock()

	for _, curr := range c.list {
		curr.close()
	}
}

func (c *connectionList) getOrRegister(peer transport.Peer) managedConnection {
	c.mux.Lock()
	defer c.mux.Unlock()

	// Check whether we're already connected to this peer (by ID)
	for _, curr := range c.list {
		if curr.peer.ID == peer.ID {
			return *curr
		}
	}

	return managedConnection{peer: peer, mux: &sync.Mutex{}}
}
