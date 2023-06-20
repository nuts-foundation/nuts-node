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
	"context"
	"github.com/nuts-foundation/nuts-node/test"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/stretchr/testify/assert"
)

func Test_conn_disconnect(t *testing.T) {
	t.Run("not connected", func(t *testing.T) {
		conn := conn{}
		conn.ctx, conn.cancelCtx = context.WithCancel(context.Background())
		conn.disconnect()
		assert.False(t, conn.IsConnected())
	})
	t.Run("connected", func(t *testing.T) {
		conn := createConnection(context.Background(), transport.Peer{}).(*conn)
		conn.streams["stream name"] = &MockStream{}
		assert.True(t, conn.IsConnected())
		conn.disconnect()
		assert.False(t, conn.IsConnected())
	})
	t.Run("resets peer ID", func(t *testing.T) {
		conn := conn{}
		conn.ctx, conn.cancelCtx = context.WithCancel(context.Background())
		conn.verifyOrSetPeerID("foo")
		conn.disconnect()
		assert.Empty(t, conn.Peer())
	})
}

func Test_conn_waitUntilDisconnected(t *testing.T) {
	t.Run("never open, should return immediately", func(t *testing.T) {
		conn := createConnection(context.Background(), transport.Peer{})
		conn.waitUntilDisconnected()
	})
	t.Run("disconnected while waiting, should return almost immediately", func(t *testing.T) {
		conn := conn{}
		conn.ctx, conn.cancelCtx = context.WithCancel(context.Background())
		wg := sync.WaitGroup{}
		wg.Add(1)
		go func() {
			wg.Wait()
			conn.disconnect()
		}()
		wg.Done()
		conn.waitUntilDisconnected()
	})
	t.Run("waiting after disconnect, should return immediately", func(t *testing.T) {
		conn := conn{}
		conn.ctx, conn.cancelCtx = context.WithCancel(context.Background())
		conn.disconnect()
		conn.waitUntilDisconnected()
	})
}

func Test_conn_registerStream(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		connection := createConnection(context.Background(), transport.Peer{}).(*conn)
		stream := newServerStream("foo", "")
		defer stream.cancelFunc()

		assert.False(t, connection.IsConnected())
		accepted := connection.registerStream(&TestProtocol{}, stream)
		assert.True(t, accepted)
		assert.True(t, connection.IsConnected())
	})
	t.Run("already connected (same protocol)", func(t *testing.T) {
		connection := createConnection(context.Background(), transport.Peer{}).(*conn)
		stream := newServerStream("foo", "")
		defer stream.cancelFunc()

		accepted := connection.registerStream(&TestProtocol{}, stream)
		accepted2 := connection.registerStream(&TestProtocol{}, stream)

		assert.True(t, accepted)
		assert.False(t, accepted2)
	})
}

func Test_conn_startSending(t *testing.T) {
	t.Run("disconnect does not panic", func(t *testing.T) {
		connection := createConnection(context.Background(), transport.Peer{}).(*conn)
		stream := newServerStream("foo", "")

		defer stream.cancelFunc()

		p := &TestProtocol{}
		_ = connection.registerStream(p, stream)

		assert.Equal(t, int32(2), connection.activeGoroutines) // startSending and startReceiving

		stream.cancelFunc()
		connection.disconnect()

		test.WaitFor(t, func() (bool, error) {
			return atomic.LoadInt32(&connection.activeGoroutines) == 0, nil
		}, 5*time.Second, "waiting for all goroutines to exit")

		// Last received message is dropped and no status is set. Default value is OK.
		assert.Equal(t, codes.OK, connection.status.Load().Code())
	})
}

func TestConn_Send(t *testing.T) {
	t.Run("buffer overflow softlimit", func(t *testing.T) {
		connection := createConnection(context.Background(), transport.Peer{}).(*conn)
		stream := newServerStream("foo", "")
		protocol := &TestProtocol{}
		_ = connection.registerStream(protocol, stream)
		connection.cancelCtx()
		time.Sleep(time.Millisecond)

		for i := 0; i < outboxSoftLimit; i++ {
			err := connection.Send(protocol, struct{}{}, false)
			require.NoError(t, err)
		}

		t.Run("outbox overflows without ignoreSoftLimit", func(t *testing.T) {
			err := connection.Send(protocol, struct{}{}, false)

			assert.EqualError(t, err, "peer's outbound message backlog has reached max desired capacity, message is dropped (peer=@,backlog-size=100)")
		})

		t.Run("outbox doesn't overflow with ignoreSoftLimit", func(t *testing.T) {
			err := connection.Send(protocol, struct{}{}, true)

			assert.NoError(t, err)
		})
	})

	t.Run("buffer overflow hardLimit", func(t *testing.T) {
		connection := createConnection(context.Background(), transport.Peer{}).(*conn)
		stream := newServerStream("foo", "")
		protocol := &TestProtocol{}
		_ = connection.registerStream(protocol, stream)
		connection.cancelCtx()
		time.Sleep(time.Millisecond)

		for i := 0; i < OutboxHardLimit; i++ {
			err := connection.Send(protocol, struct{}{}, true)
			require.NoError(t, err)
		}

		t.Run("outbox overflows without ignoreSoftLimit", func(t *testing.T) {
			err := connection.Send(protocol, struct{}{}, true)

			assert.EqualError(t, err, "peer's outbound message backlog has reached hard limit, message is dropped (peer=@,backlog-size=5000)")
		})
	})
}
