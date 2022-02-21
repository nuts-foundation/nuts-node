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
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/test"
	"github.com/stretchr/testify/assert"
	"go.uber.org/atomic"
)

func TestQueue_start(t *testing.T) {
	t.Run("ticker ticks at a set interval", func(t *testing.T) {
		q := peerQueue{}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		ch := q.start(ctx, time.Nanosecond)
		val := <-ch

		assert.True(t, val)
	})

	t.Run("ticker channel returns false when closed", func(t *testing.T) {
		q := peerQueue{}
		ctx, cancel := context.WithCancel(context.Background())

		ch := q.start(ctx, time.Second)
		cancel()
		val := <-ch

		assert.False(t, val)
	})
}

func TestQueue_stop(t *testing.T) {
	t.Run("stop stops the ticker", func(t *testing.T) {
		q := peerQueue{}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		ch := q.start(ctx, time.Second)
		q.stop()
		val := <-ch

		assert.False(t, val)
	})

	t.Run("stop does not ends the parent ctx", func(t *testing.T) {
		q := peerQueue{}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		_ = q.start(ctx, time.Second)
		q.stop()

		assert.NoError(t, ctx.Err())
	})
}

func TestQueue_do(t *testing.T) {
	q := peerQueue{}
	wg := sync.WaitGroup{}
	wg.Add(1)
	done1 := atomic.NewBool(false)
	done2 := atomic.NewBool(false)

	go q.do(func() {
		wg.Wait()
		done1.Toggle()
	})

	go q.do(func() {
		done2.Toggle()
	})

	assert.False(t, done1.Load())
	assert.False(t, done2.Load())
	wg.Done()
	test.WaitFor(t, func() (bool, error) {
		return done1.Load(), nil
	}, 50*time.Millisecond, "timeout while waiting for mutexes")
	assert.True(t, done1.Load())
	assert.True(t, done2.Load())
}

func TestQueue_enqueued(t *testing.T) {
	t.Run("is empty for new queue", func(t *testing.T) {
		pq := newPeerQueue()

		assert.Empty(t, pq.enqueued())
	})

	t.Run("returns enqueued transaction references", func(t *testing.T) {
		pq := newPeerQueue()
		pq.enqueue(hash.EmptyHash())

		enq := pq.enqueued()

		if !assert.Len(t, enq, 1) {
			return
		}
		assert.Equal(t, hash.EmptyHash(), enq[0])
	})
}
func TestQueue_enqueue(t *testing.T) {
	t.Run("adds entries to queue and set", func(t *testing.T) {
		pq := newPeerQueue()

		pq.enqueue(hash.EmptyHash())

		assert.Equal(t, 1, pq.queue.Len())
	})

	t.Run("does not add entry when present in log", func(t *testing.T) {
		pq := newPeerQueue()

		pq.received(hash.EmptyHash())
		pq.enqueue(hash.EmptyHash())

		assert.Equal(t, 0, pq.queue.Len())
	})

	t.Run("does not add entry when full", func(t *testing.T) {
		pq := newPeerQueue()
		pq.maxSize = 10
		set := make([]hash.SHA256Hash, 10)
		for i := 0; i < 10; i++ {
			set[i] = hash.SHA256Sum([]byte{byte(i & 0xff)})
		}

		pq.enqueue(hash.EmptyHash())
		pq.enqueue(set...)

		assert.Equal(t, 10, pq.queue.Len())
	})
}

func TestQueue_clear(t *testing.T) {
	t.Run("empties queue and set", func(t *testing.T) {
		pq := newPeerQueue()
		pq.enqueue(hash.EmptyHash())

		pq.clear()

		assert.Equal(t, 0, pq.queue.Len())
	})

	t.Run("does not empty log", func(t *testing.T) {
		pq := newPeerQueue()
		pq.received(hash.EmptyHash())

		pq.clear()

		assert.Equal(t, 1, pq.log.Len())
	})
}

func TestQueue_received(t *testing.T) {
	t.Run("adds entries to log", func(t *testing.T) {
		pq := newPeerQueue()

		pq.received(hash.EmptyHash())

		assert.Equal(t, 1, pq.log.Len())
	})

	t.Run("removes oldest entries when full", func(t *testing.T) {
		pq := newPeerQueue()
		pq.maxSize = 1

		pq.received(hash.SHA256Sum([]byte{1}))
		pq.received(hash.EmptyHash())

		assert.Equal(t, 1, pq.log.Len())
	})

	t.Run("removes elements from queue", func(t *testing.T) {
		pq := newPeerQueue()
		pq.maxSize = 1

		pq.enqueue(hash.EmptyHash())
		pq.received(hash.EmptyHash())

		assert.Equal(t, 0, pq.queue.Len())
	})
}
