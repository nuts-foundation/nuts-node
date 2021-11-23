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
	"github.com/nuts-foundation/nuts-node/test"
	"github.com/stretchr/testify/assert"
	"sync/atomic"
	"testing"
	"time"
)

func Test_conn_close(t *testing.T) {
	t.Run("no context", func(t *testing.T) {
		conn := conn{}
		conn.close()
	})
	t.Run("close cancels context", func(t *testing.T) {
		called := false
		conn := conn{
			cancelCtx: func() {
				called = true
			},
		}
		conn.close()
		assert.True(t, called)
	})
	t.Run("resets peer ID", func(t *testing.T) {
		conn := conn{}
		conn.verifyOrSetPeerID("foo")
		conn.close()
		assert.Empty(t, conn.getPeer())
	})
}

func Test_conn_registerServerStream(t *testing.T) {
	t.Run("cancelling before-last stream does not invoke callback", func(t *testing.T) {
		called := atomic.Value{}
		called.Store(false)
		conn := createConnection(nil, transport.Peer{}, func(connection managedConnection) {
			called.Store(true)
		}).(*conn)
		stream1 := newServerStream("foo", "")
		stream2 := newServerStream("foo", "")
		conn.registerServerStream(stream1)
		conn.registerServerStream(stream2)
		stream1.cancelFunc()

		test.WaitFor(t, func() (bool, error) {
			conn.mux.Lock()
			defer conn.mux.Unlock()
			return len(conn.grpcInboundStreams) == 1, nil
		}, time.Second, "time-out while waiting for closed stream to be cleaned up")

		assert.False(t, called.Load().(bool))
	})
	t.Run("cancelling last stream invokes callback", func(t *testing.T) {
		called := atomic.Value{}
		called.Store(false)
		conn := createConnection(nil, transport.Peer{}, func(connection managedConnection) {
			called.Store(true)
		}).(*conn)
		stream := newServerStream("foo", "")
		conn.registerServerStream(stream)
		stream.cancelFunc()

		test.WaitFor(t, func() (bool, error) {
			conn.mux.Lock()
			defer conn.mux.Unlock()
			return len(conn.grpcInboundStreams) == 0, nil
		}, time.Second, "time-out while waiting for closed stream to be cleaned up")

		assert.True(t, called.Load().(bool))
	})
}
