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
	"container/list"
	"context"
	"sync"
	"time"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
)

// peerQueue contains a log of received transaction references and a queue of references to send for a specific peer.
type peerQueue struct {
	// cancelFunc to stop the ticker for this peer
	cancelFunc context.CancelFunc
	// log of recent received transaction hashes
	log *list.List
	// logSet contains the same set as log, but then as indexed set.
	logSet map[string]*list.Element
	// maxSize determines how many items are kept in each list
	maxSize int
	// mutex to protect concurrent access to the queue
	mutex sync.Mutex
	// queue that holds the list of hashes to be gossipped
	queue *list.List
	// set contains the items from the queue but as indexed set
	set map[string]*list.Element
}

func newPeerQueue() peerQueue {
	return peerQueue{
		log:     list.New(),
		logSet:  map[string]*list.Element{},
		maxSize: maxQueueSize,
		queue:   list.New(),
		set:     map[string]*list.Element{},
	}
}

// start a ticker. It'll use the given context as parent context to stop the ticker
func (pq *peerQueue) start(parentCtx context.Context, interval time.Duration) <-chan bool {
	var ctx context.Context
	ctx, pq.cancelFunc = context.WithCancel(parentCtx)
	done := ctx.Done()
	returnChan := make(chan bool, 1)

	go func() {
	outer:
		for {
			select {
			case <-done:
				break outer
			case <-time.Tick(interval):
				returnChan <- true
			}
		}
		// send a false over the channel
		close(returnChan)
	}()

	return returnChan
}

func (pq *peerQueue) stop() {
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
func (pq *peerQueue) enqueued() []hash.SHA256Hash {
	refs := make([]hash.SHA256Hash, pq.queue.Len())
	i := 0
	for element := pq.queue.Front(); element != nil; element = element.Next() {
		refs[i] = element.Value.(hash.SHA256Hash)
		i++
	}
	return refs
}

// clear the queue, it does not clear the log
// it does not lock the mutex
func (pq *peerQueue) clear() {
	pq.queue = list.New()
	pq.set = map[string]*list.Element{}
}

// received adds given hashes to the log and removes them from the queue when present
func (pq *peerQueue) received(refs ...hash.SHA256Hash) {
	pq.mutex.Lock()
	defer pq.mutex.Unlock()

	for _, ref := range refs {
		if _, ok := pq.logSet[ref.String()]; !ok {
			pq.logSet[ref.String()] = pq.log.PushBack(ref)
		}

		// remove from queue
		if element, ok := pq.set[ref.String()]; ok {
			pq.queue.Remove(element)
			delete(pq.set, ref.String())
		}

		// shrink log
		if pq.log.Len() > pq.maxSize {
			if element := pq.log.Front(); element != nil {
				data := element.Value.(hash.SHA256Hash)
				delete(pq.logSet, data.String())
				pq.log.Remove(element)
			}
		}
	}
}

// enqueue adds given hashes to the queue unless present in the log
func (pq *peerQueue) enqueue(refs ...hash.SHA256Hash) {
	pq.mutex.Lock()
	defer pq.mutex.Unlock()

	if pq.queue.Len() >= pq.maxSize {
		// ignore new, older TXs are more important to process first for peer
		return
	}

	for _, ref := range refs {
		// ignore if present in log
		if _, ok := pq.logSet[ref.String()]; ok {
			continue
		}

		// add to queue
		pq.set[ref.String()] = pq.queue.PushBack(ref)
	}
}
