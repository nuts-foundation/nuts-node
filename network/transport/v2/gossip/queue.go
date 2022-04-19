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

	"github.com/nuts-foundation/nuts-node/crypto/hash"
)

// peerQueue contains a log of received transaction references and a queue of references to send for a specific peer.
type peerQueue struct {
	// cancelFunc to unregister the ticker for this peer
	cancelFunc context.CancelFunc
	// log of recent received transaction hashes
	log *uniqueList
	// maxSize determines how many items are kept in each list
	maxSize int
	// mutex to protect concurrent access to the queue
	mutex sync.Mutex
	// queue that holds the list of hashes to be gossipped
	queue *uniqueList
	xor   hash.SHA256Hash
	clock uint32
}

func newPeerQueue() peerQueue {
	return peerQueue{
		log:     newUniqueList(),
		maxSize: maxQueueSize,
		queue:   newUniqueList(),
	}
}

// registerContext registers a context. When unregister is called it'll cancel the returned context.
func (pq *peerQueue) registerContext(parentCtx context.Context) context.Context {
	var ctx context.Context
	ctx, pq.cancelFunc = context.WithCancel(parentCtx)

	return ctx
}

func (pq *peerQueue) unregister() {
	if pq.cancelFunc != nil {
		pq.cancelFunc()
	}
}

// lock and do stuff
func (pq *peerQueue) do(f func()) {
	pq.mutex.Lock()
	defer pq.mutex.Unlock()

	f()
}

// enqueued returns the enqueued transaction references
// it does not lock the mutex
func (pq *peerQueue) enqueued() ([]hash.SHA256Hash, hash.SHA256Hash, uint32) {
	return pq.queue.Values(), pq.xor, pq.clock
}

// clear the queue, it does not clear the log
// it does not lock the mutex
func (pq *peerQueue) clear() {
	pq.queue = newUniqueList()
}

// logReceivedTransactions adds given hashes to the log and removes them from the queue when present
func (pq *peerQueue) logReceivedTransactions(refs ...hash.SHA256Hash) {
	pq.mutex.Lock()
	defer pq.mutex.Unlock()

	for _, ref := range refs {
		// add to log
		pq.log.Add(ref)

		// remove from queue
		pq.queue.Remove(ref)

		// shrink log if too big
		if pq.log.Len() > pq.maxSize {
			pq.log.RemoveFront()
		}
	}
}

// enqueue adds given hashes to the queue unless present in the log
func (pq *peerQueue) enqueue(clock uint32, xor hash.SHA256Hash, refs ...hash.SHA256Hash) {
	pq.mutex.Lock()
	defer pq.mutex.Unlock()

	pq.xor = xor
	pq.clock = clock

	for _, ref := range refs {
		if pq.queue.Len() >= pq.maxSize {
			// ignore new, older TXs are more important to process first for peer
			return
		}

		// ignore if present in log
		if pq.log.Contains(ref) {
			continue
		}

		// add to queue
		pq.queue.Add(ref)
	}
}
