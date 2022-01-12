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
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/stretchr/testify/assert"
	"sync"
	"testing"
)

func Test_conn_disconnect(t *testing.T) {
	t.Run("not connected", func(t *testing.T) {
		conn := conn{}
		conn.disconnect()
		assert.False(t, conn.IsConnected())
	})
	t.Run("connected", func(t *testing.T) {
		conn := conn{}
		conn.ctx, conn.cancelCtx = context.WithCancel(context.Background())
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
		conn := conn{}
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
		connection := createConnection(context.Background(), nil, transport.Peer{}).(*conn)
		stream := newServerStream("foo", "")
		defer stream.cancelFunc()

		assert.False(t, connection.IsConnected())
		accepted := connection.registerStream(&TestProtocol{}, stream)
		assert.True(t, accepted)
		assert.True(t, connection.IsConnected())
	})
	t.Run("already connected (same protocol)", func(t *testing.T) {
		connection := createConnection(context.Background(), nil, transport.Peer{}).(*conn)
		stream := newServerStream("foo", "")
		defer stream.cancelFunc()

		accepted := connection.registerStream(&TestProtocol{}, stream)
		accepted2 := connection.registerStream(&TestProtocol{}, stream)

		assert.True(t, accepted)
		assert.False(t, accepted2)
	})
}
