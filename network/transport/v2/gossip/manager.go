/*
 * Nuts node
 * Copyright (C) 2022 Nuts community
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

package gossip

import (
	"context"
	"sync"
	"time"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/network/transport"
)

const maxQueueSize = 100

// SenderFunc is called from the queue ticker at the set interval.
// If it's successful it'll return true. This will empty the queue for that peer.
// All senders must succeed in order for the queue to be emptied.
type SenderFunc func(id transport.PeerID, refs []hash.SHA256Hash) bool

// Manager handles changes in connections, new transactions and updates from other Gossip messages.
// It keeps track of transaction hashes that still have to be send to a peer in a queue.
// If a peer gossips a particular hash, that hash is removed from the peer queue to unneeded traffic.
// It also keeps a small log of received hashes from a peer.
//When a transaction is added to the DAG but exists in that log, it won't be gossipped to that peer.
type Manager interface {
	// GossipReceived is to be called each time a peer sends a Gossip message.
	// All hashes should be removed from the peer's queue and added to the log.
	GossipReceived(id transport.PeerID, refs ...hash.SHA256Hash)
	// PeerConnected is to be called when a new peer connects. A new gossip queue will then be created for this peer.
	// It will also start a ticker for this peer.
	PeerConnected(peer transport.Peer)
	// PeerDisconnected is to be called when a peer disconnects. The gossip queue can then be cleared.
	PeerDisconnected(peer transport.Peer)
	// RegisterSender registers a sender function. The manager will call this function at set intervals to send a gossip message.
	RegisterSender(SenderFunc)
	// TransactionRegistered is to be called when a new transaction is added to the DAG.
	TransactionRegistered(transaction hash.SHA256Hash)
}

type manager struct {
	// ctx is the context that is used to stop all tickers
	ctx context.Context
	// interval to tick
	interval time.Duration
	// mutex to protect concurrent access to the peer administration
	mutex sync.RWMutex
	// senders contains all registered senders
	senders []SenderFunc
	// peers maps peerID to peerQueue
	peers map[string]*peerQueue
}

// NewManager returns a new gossip Manager
// The context passed must be cancelable so the ticker can listen to the done channel
func NewManager(ctx context.Context, interval time.Duration) Manager {
	return &manager{
		ctx:      ctx,
		interval: interval,
		peers:    map[string]*peerQueue{},
	}
}

func (m *manager) GossipReceived(id transport.PeerID, refs ...hash.SHA256Hash) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	peer, ok := m.peers[string(id)]
	if !ok {
		log.Logger().Errorf("received gossip from peer, but gossip administration is missing, peer=%s", string(id))
		return
	}

	peer.received(refs...)
}

func (m *manager) PeerConnected(transportPeer transport.Peer) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// ignore adding a peer if it already exists
	if _, ok := m.peers[string(transportPeer.ID)]; ok {
		return
	}

	pq := newPeerQueue()
	m.peers[string(transportPeer.ID)] = &pq

	// start ticker for this peer
	tickChan := pq.start(m.ctx, m.interval)
	done := m.ctx.Done()
	// copy from manager to avoid race conditions and locking
	senders := m.senders
	go func() {
		for {
			select {
			case <-done:
				return
			case val := <-tickChan:
				// peer context cancelled
				if !val {
					return
				}
				callSenders(transportPeer.ID, &pq, senders)
			}
		}
	}()
}

func callSenders(id transport.PeerID, peer *peerQueue, senders []SenderFunc) {
	peer.do(func() {
		refs := peer.enqueued()

		shouldClear := true
		for _, sender := range senders {
			if !sender(id, refs) {
				shouldClear = false
			}
		}

		if shouldClear {
			peer.clear()
		}
	})
}

func (m *manager) PeerDisconnected(transportPeer transport.Peer) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	peer, ok := m.peers[string(transportPeer.ID)]

	// ignore removing a peer if it doesn't exists
	if !ok {
		return
	}

	// stop ticker
	peer.stop()

	delete(m.peers, string(transportPeer.ID))
}

func (m *manager) RegisterSender(f SenderFunc) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.senders = append(m.senders, f)
}

func (m *manager) TransactionRegistered(transaction hash.SHA256Hash) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	for _, peer := range m.peers {
		peer.enqueue(transaction)
	}
}
