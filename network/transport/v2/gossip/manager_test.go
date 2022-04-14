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
	"go.uber.org/goleak"
	"sync"
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/stretchr/testify/assert"
)

func TestNewManager(t *testing.T) {
	ctx := context.Background()
	interval := time.Millisecond

	gMan := NewManager(ctx, interval).(*manager)

	assert.Equal(t, ctx, gMan.ctx)
	assert.Equal(t, interval, gMan.interval)
	assert.NotNil(t, gMan.peers)
}

func TestManager_PeerConnected(t *testing.T) {
	t.Run("adds a peer to the administration", func(t *testing.T) {
		gMan := giveMeAgMan(t)

		gMan.PeerConnected(transport.Peer{ID: "1"})

		assert.NotNil(t, gMan.peers["1"])
	})

	t.Run("skips existing peers", func(t *testing.T) {
		gMan := giveMeAgMan(t)
		gMan.PeerConnected(transport.Peer{ID: "1"})
		gMan.TransactionRegistered(hash.EmptyHash())

		// doesn't influence queue
		gMan.PeerConnected(transport.Peer{ID: "1"})
		pq := gMan.peers["1"]

		assert.Equal(t, 1, pq.queue.Len())
	})
}

func TestManager_PeerDisconnected(t *testing.T) {
	t.Run("removes peer from the administration", func(t *testing.T) {
		gMan := giveMeAgMan(t)
		peer := transport.Peer{ID: "1"}
		gMan.PeerConnected(peer)

		gMan.PeerDisconnected(peer)
		_, present := gMan.peers["1"]

		assert.False(t, present)
	})

	t.Run("ignores unknown peers", func(t *testing.T) {
		gMan := giveMeAgMan(t)
		peer := transport.Peer{ID: "1"}
		gMan.PeerConnected(peer)

		gMan.PeerDisconnected(transport.Peer{ID: "2"})
		_, present1 := gMan.peers["1"]
		_, present2 := gMan.peers["2"]

		assert.True(t, present1)
		assert.False(t, present2)
	})

	t.Run("stops ticker", func(t *testing.T) {
		// Use uber/goleak to assert the goroutine started by PeerConnected is stopped when PeerDisconnected is called
		defer goleak.VerifyNone(t)

		gMan := giveMeAgMan(t)
		peer := transport.Peer{ID: "1"}
		gMan.peers["2"] = gMan.peers["1"]

		wg := sync.WaitGroup{}
		wg.Add(1)
		gMan.RegisterSender(func(id transport.PeerID, refs []hash.SHA256Hash) bool {
			wg.Done()
			return true
		})
		gMan.PeerConnected(peer)
		wg.Wait()

		gMan.PeerDisconnected(peer)
		gMan.peers["1"] = gMan.peers["2"] // reset administration to bypass administration test
	})
}

func TestManager_GossipReceived(t *testing.T) {
	t.Run("ignores received gossip when administration is missing", func(t *testing.T) {
		gMan := giveMeAgMan(t)

		gMan.GossipReceived("1", hash.EmptyHash())

		// see? nothing exploded!
	})

	t.Run("updates the log of the peerQueue", func(t *testing.T) {
		gMan := giveMeAgMan(t)
		gMan.PeerConnected(transport.Peer{ID: "1"})

		gMan.GossipReceived("1", hash.EmptyHash())

		pq := gMan.peers["1"]
		assert.Equal(t, 1, pq.log.Len())
	})
}

func TestManager_callSenders(t *testing.T) {
	t.Run("ok - called and peerQueue cleared", func(t *testing.T) {
		gMan := giveMeAgMan(t)
		gMan.PeerConnected(transport.Peer{ID: "1"})
		gMan.RegisterSender(func(id transport.PeerID, refs []hash.SHA256Hash) bool {
			return true
		})
		gMan.TransactionRegistered(hash.EmptyHash())

		pq := gMan.peers["1"]
		callSenders("1", pq, gMan.messageSenders)

		assert.Equal(t, 0, pq.queue.Len())
	})

	t.Run("not ok - called and peerQueue not cleared", func(t *testing.T) {
		gMan := giveMeAgMan(t)
		gMan.PeerConnected(transport.Peer{ID: "1"})
		gMan.RegisterSender(func(id transport.PeerID, refs []hash.SHA256Hash) bool {
			return false
		})
		gMan.TransactionRegistered(hash.EmptyHash())

		pq := gMan.peers["1"]
		callSenders("1", pq, gMan.messageSenders)

		assert.Equal(t, 1, pq.queue.Len())
	})
}

func giveMeAgMan(t *testing.T) *manager {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel() })
	gMan := NewManager(ctx, time.Millisecond).(*manager)

	return gMan
}
