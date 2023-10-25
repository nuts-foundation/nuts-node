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
	"github.com/stretchr/testify/require"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"

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
	peer := transport.Peer{ID: "1"}
	t.Run("adds a peer to the administration", func(t *testing.T) {
		gMan := giveMeAgMan(t)

		gMan.PeerConnected(peer, hash.SHA256Sum([]byte{1, 2, 3}), 5)

		require.NotNil(t, gMan.peers[peer.Key()])
		assert.Equal(t, uint32(5), gMan.peers[peer.Key()].clock)
		assert.Equal(t, hash.SHA256Sum([]byte{1, 2, 3}), gMan.peers[peer.Key()].xor)
	})

	t.Run("skips existing peers", func(t *testing.T) {
		gMan := giveMeAgMan(t)
		gMan.PeerConnected(transport.Peer{ID: "1"}, hash.EmptyHash(), 5)
		gMan.TransactionRegistered(hash.EmptyHash(), hash.EmptyHash(), 5)

		// doesn't influence queue
		gMan.PeerConnected(peer, hash.EmptyHash(), 5)
		pq := gMan.peers[peer.Key()]

		assert.Equal(t, 1, pq.queue.Len())
	})
}

func TestManager_PeerDisconnected(t *testing.T) {
	t.Run("removes peer from the administration", func(t *testing.T) {
		gMan := giveMeAgMan(t)
		peer := transport.Peer{ID: "1"}
		gMan.PeerConnected(peer, hash.EmptyHash(), 5)

		gMan.PeerDisconnected(peer)
		_, present := gMan.peers["1"]

		assert.False(t, present)
	})

	t.Run("ignores unknown peers", func(t *testing.T) {
		gMan := giveMeAgMan(t)
		peer := transport.Peer{ID: "1"}
		peer2 := transport.Peer{ID: "2"}
		gMan.PeerConnected(peer, hash.EmptyHash(), 5)

		gMan.PeerDisconnected(peer2)
		_, present1 := gMan.peers[peer.Key()]
		_, present2 := gMan.peers[peer2.Key()]

		assert.True(t, present1)
		assert.False(t, present2)
	})

	t.Run("stops ticker", func(t *testing.T) {
		// Use uber/goleak to assert the goroutine started by PeerConnected is stopped when PeerDisconnected is called
		defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

		gMan := giveMeAgMan(t)
		gMan.interval = time.Millisecond
		peer := transport.Peer{ID: "1"}
		peer2 := transport.Peer{ID: "2"}
		gMan.peers[peer2.Key()] = gMan.peers[peer.Key()]

		once := sync.Once{}
		wg := sync.WaitGroup{}
		wg.Add(1)
		gMan.RegisterSender(func(peer transport.Peer, refs []hash.SHA256Hash, xor hash.SHA256Hash, clock uint32) bool {
			once.Do(func() {
				wg.Done()
			})
			return true
		})
		gMan.PeerConnected(peer, hash.EmptyHash(), 5)
		wg.Wait()

		gMan.PeerDisconnected(peer)
		gMan.peers["1"] = gMan.peers["2"] // reset administration to bypass administration test
	})
}

func TestManager_GossipReceived(t *testing.T) {
	peer := transport.Peer{ID: "1"}
	t.Run("ignores received g"+
		"ossip when administration is missing", func(t *testing.T) {
		gMan := giveMeAgMan(t)

		gMan.GossipReceived(peer, hash.EmptyHash())

		// see? nothing exploded!
	})

	t.Run("updates the log of the peerQueue", func(t *testing.T) {
		gMan := giveMeAgMan(t)
		gMan.PeerConnected(peer, hash.EmptyHash(), 5)

		gMan.GossipReceived(peer, hash.EmptyHash())

		pq := gMan.peers[peer.Key()]
		assert.Equal(t, 1, pq.log.Len())
	})
}

func TestManager_callSenders(t *testing.T) {
	peer := transport.Peer{ID: "1"}

	t.Run("ok - called and peerQueue cleared", func(t *testing.T) {
		gMan := giveMeAgMan(t)
		gMan.PeerConnected(transport.Peer{ID: "1"}, hash.EmptyHash(), 5)
		gMan.RegisterSender(func(peer transport.Peer, refs []hash.SHA256Hash, xor hash.SHA256Hash, clock uint32) bool {
			return true
		})
		gMan.TransactionRegistered(hash.EmptyHash(), hash.EmptyHash(), 5)

		pq := gMan.peers[peer.Key()]
		callSenders(peer, pq, gMan.messageSenders)

		assert.Equal(t, 0, pq.queue.Len())
	})

	t.Run("not ok - called and peerQueue not cleared", func(t *testing.T) {
		gMan := giveMeAgMan(t)
		gMan.PeerConnected(peer, hash.EmptyHash(), 5)
		gMan.RegisterSender(func(peer transport.Peer, refs []hash.SHA256Hash, xor hash.SHA256Hash, clock uint32) bool {
			return false
		})
		gMan.TransactionRegistered(hash.EmptyHash(), hash.EmptyHash(), 5)

		pq := gMan.peers[peer.Key()]
		callSenders(peer, pq, gMan.messageSenders)

		assert.Equal(t, 1, pq.queue.Len())
	})
}

func giveMeAgMan(t *testing.T) *manager {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel() })
	gMan := NewManager(ctx, time.Second).(*manager)

	return gMan
}
