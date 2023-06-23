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
	"github.com/nuts-foundation/nuts-node/core"
	"sync"
	"time"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/network/transport"
)

const maxQueueSize = 100

// SenderFunc is called from the queue ticker at the set interval.
// The func should send a specific network message within its body.
// If it's successful it'll return true. This will empty the queue for that peer.
// All messageSenders must succeed in order for the queue to be emptied.
type SenderFunc func(peer transport.Peer, refs []hash.SHA256Hash, xor hash.SHA256Hash, clock uint32) bool

// Manager handles changes in connections, new transactions and updates from other Gossip messages.
// It keeps track of transaction hashes that still have to be send to a peer in a queue.
// If a peer gossips a particular hash, that hash is removed from the peer queue to reduce traffic.
// It also keeps a small log of received hashes from a peer.
// When a transaction is added to the DAG but exists in that log, it won't be gossipped to that peer.
type Manager interface {
	// GossipReceived is to be called each time a peer sends a Gossip message.
	// All hashes should be removed from the peer's queue and added to the log.
	GossipReceived(peer transport.Peer, refs ...hash.SHA256Hash)
	// PeerConnected is to be called when a new peer connects. A new gossip queue will then be created for this peer.
	// The initial XOR and clock values must be supplied, because they're only updated when a transaction is added to the DAG.
	PeerConnected(peer transport.Peer, xor hash.SHA256Hash, clock uint32)
	// PeerDisconnected is to be called when a peer disconnects. The gossip queue can then be cleared.
	PeerDisconnected(peer transport.Peer)
	// RegisterSender registers a sender function. The manager will call this function at set intervals to send a gossip message.
	// Senders should not be added after configuration.
	RegisterSender(SenderFunc)
	// TransactionRegistered is to be called when a new transaction is added to the DAG.
	TransactionRegistered(transaction hash.SHA256Hash, xor hash.SHA256Hash, clock uint32)
}

type manager struct {
	// ctx is the context that is used to unregister all tickers
	ctx context.Context
	// interval to tick
	interval time.Duration
	// mutex to protect concurrent access to the peer administration
	mutex sync.RWMutex
	// messageSenders contains all registered functions that should send network messages
	messageSenders []SenderFunc
	// peers maps peer.Key to peerQueue
	peers map[transport.PeerKey]*peerQueue
}

// NewManager returns a new gossip Manager
// The context passed must be cancelable so the ticker can listen to the done channel
func NewManager(ctx context.Context, interval time.Duration) Manager {
	return &manager{
		ctx:      ctx,
		interval: interval,
		peers:    map[transport.PeerKey]*peerQueue{},
	}
}

func (m *manager) GossipReceived(transportPeer transport.Peer, refs ...hash.SHA256Hash) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	peer, ok := m.peers[transportPeer.Key()]
	if !ok {
		log.Logger().
			WithField(core.LogFieldPeerID, transportPeer.ID).
			Error("Received gossip from peer, but gossip administration is missing")
		return
	}

	peer.logReceivedTransactions(refs...)
}

func (m *manager) PeerConnected(transportPeer transport.Peer, xor hash.SHA256Hash, clock uint32) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// ignore adding a peer if it already exists
	if _, ok := m.peers[transportPeer.Key()]; ok {
		return
	}

	pq := newPeerQueue()
	pq.clock = clock
	pq.xor = xor
	m.peers[transportPeer.Key()] = &pq

	// make a subContext

	subContext := pq.registerContext(m.ctx)
	done := subContext.Done()
	senders := m.messageSenders
	go func() {
		ticker := time.NewTicker(m.interval)
		for {
			select {
			case <-done:
				// stop ticker and exit when queue.unregister is called.
				ticker.Stop()
				return
			case <-ticker.C:
				callSenders(transportPeer, &pq, senders)
			}
		}
	}()
}

func callSenders(transportPeer transport.Peer, peer *peerQueue, senders []SenderFunc) {
	peer.do(func() {
		refs, xor, clock := peer.enqueued()

		shouldClear := true
		for _, sender := range senders {
			if !sender(transportPeer, refs, xor, clock) {
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

	peer, ok := m.peers[transportPeer.Key()]

	// ignore removing a peer if it doesn't exists
	if !ok {
		return
	}

	// unregister ticker
	peer.unregister()

	delete(m.peers, transportPeer.Key())
}

func (m *manager) RegisterSender(f SenderFunc) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.messageSenders = append(m.messageSenders, f)
}

func (m *manager) TransactionRegistered(transaction hash.SHA256Hash, xor hash.SHA256Hash, clock uint32) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	for _, peer := range m.peers {
		peer.enqueue(clock, xor, transaction)
	}
}
