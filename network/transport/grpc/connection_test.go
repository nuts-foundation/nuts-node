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
	"io"
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
		conn := createConnection(context.Background(), transport.Peer{}, 0).(*conn)
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
		conn := createConnection(context.Background(), transport.Peer{}, 0)
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
		connection := createConnection(context.Background(), transport.Peer{}, 0).(*conn)
		stream := newServerStream("foo", "", nil)
		defer stream.cancelFunc()

		assert.False(t, connection.IsConnected())
		accepted := connection.registerStream(&TestProtocol{}, stream)
		assert.True(t, accepted)
		assert.True(t, connection.IsConnected())
	})
	t.Run("already connected (same protocol)", func(t *testing.T) {
		connection := createConnection(context.Background(), transport.Peer{}, 0).(*conn)
		stream := newServerStream("foo", "", nil)
		defer stream.cancelFunc()

		accepted := connection.registerStream(&TestProtocol{}, stream)
		accepted2 := connection.registerStream(&TestProtocol{}, stream)

		assert.True(t, accepted)
		assert.False(t, accepted2)
	})
}

func Test_conn_startSending(t *testing.T) {
	t.Run("disconnect does not panic", func(t *testing.T) {
		connection := createConnection(context.Background(), transport.Peer{}, 0).(*conn)
		stream := newServerStream("foo", "", nil)

		defer stream.cancelFunc()

		p := &TestProtocol{}
		_ = connection.registerStream(p, stream)

		assert.Equal(t, int32(2), connection.activeGoroutines) // startSending and startReceiving

		// Disconnect before cancelling the stream: this guarantees the connection context is
		// cancelled before RecvMsg returns, so the receive loop drops the message instead of
		// racing to store the stream error as close status.
		connection.disconnect()
		stream.cancelFunc()

		test.WaitFor(t, func() (bool, error) {
			return atomic.LoadInt32(&connection.activeGoroutines) == 0, nil
		}, 5*time.Second, "waiting for all goroutines to exit")

		// A deliberate local disconnect must not record a close error. Default value is OK.
		assert.Equal(t, codes.OK, connection.status.Load().Code())
	})
}

func TestConn_Send(t *testing.T) {
	t.Run("buffer overflow softlimit", func(t *testing.T) {
		connection := createConnection(context.Background(), transport.Peer{}, 0).(*conn)
		stream := newServerStream("foo", "", nil)
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
		connection := createConnection(context.Background(), transport.Peer{}, 0).(*conn)
		stream := newServerStream("foo", "", nil)
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

// noopHandleProtocol is a TestProtocol that accepts received messages instead of panicking.
type noopHandleProtocol struct {
	*TestProtocol
}

func (noopHandleProtocol) Handle(Connection, interface{}) error {
	return nil
}

// tickingStream delivers an (empty) message at every interval until its context is cancelled.
type tickingStream struct {
	*stubServerStream
	interval time.Duration
}

func (s tickingStream) RecvMsg(_ interface{}) error {
	select {
	case <-time.After(s.interval):
		return nil
	case <-s.ctx.Done():
		return io.EOF
	}
}

// slowHandleProtocol is a TestProtocol whose Handle blocks for the given duration.
type slowHandleProtocol struct {
	*TestProtocol
	started  chan struct{}
	duration time.Duration
}

func (p slowHandleProtocol) Handle(Connection, interface{}) error {
	close(p.started)
	time.Sleep(p.duration)
	return nil
}

// oneMessageStream delivers a single (empty) message immediately, then blocks until its context is cancelled.
type oneMessageStream struct {
	*stubServerStream
	delivered atomic.Bool
}

func (s *oneMessageStream) RecvMsg(_ interface{}) error {
	if s.delivered.CompareAndSwap(false, true) {
		return nil
	}
	<-s.ctx.Done()
	return io.EOF
}

func Test_conn_idleTimeout(t *testing.T) {
	t.Run("disconnects when no message is received within the idle timeout", func(t *testing.T) {
		connection := createConnection(context.Background(), transport.Peer{}, 0).(*conn)
		connection.idleTimeout = 50 * time.Millisecond
		stream := newServerStream("foo", "", nil) // RecvMsg blocks until the stream is cancelled
		defer stream.cancelFunc()

		require.True(t, connection.registerStream(&TestProtocol{}, stream))

		select {
		case <-connection.ctx.Done():
		case <-time.After(2 * time.Second):
			t.Fatal("connection was not closed after idle timeout")
		}
		assert.False(t, connection.IsConnected())
	})
	t.Run("stays connected while messages are received", func(t *testing.T) {
		connection := createConnection(context.Background(), transport.Peer{}, 0).(*conn)
		connection.idleTimeout = 100 * time.Millisecond
		stream := tickingStream{stubServerStream: newServerStream("foo", "", nil), interval: 20 * time.Millisecond}
		defer stream.cancelFunc()

		require.True(t, connection.registerStream(noopHandleProtocol{&TestProtocol{}}, stream))

		select {
		case <-connection.ctx.Done():
			t.Fatal("connection was closed although messages were being received")
		case <-time.After(400 * time.Millisecond):
		}
		assert.True(t, connection.IsConnected())
	})
	t.Run("stays connected while a message is being handled", func(t *testing.T) {
		// e.g. during initial sync, handling a large transaction list may take longer than the idle timeout
		connection := createConnection(context.Background(), transport.Peer{}, 0).(*conn)
		connection.idleTimeout = 50 * time.Millisecond
		stream := &oneMessageStream{stubServerStream: newServerStream("foo", "", nil)}
		defer stream.cancelFunc()
		handling := make(chan struct{})
		protocol := slowHandleProtocol{TestProtocol: &TestProtocol{}, started: handling, duration: 400 * time.Millisecond}

		require.True(t, connection.registerStream(protocol, stream))

		<-handling
		select {
		case <-connection.ctx.Done():
			t.Fatal("connection was closed while a message was being handled")
		case <-time.After(300 * time.Millisecond):
		}
		assert.True(t, connection.IsConnected())
	})
	t.Run("zero idle timeout disables the check", func(t *testing.T) {
		connection := createConnection(context.Background(), transport.Peer{}, 0).(*conn)
		stream := newServerStream("foo", "", nil)
		defer stream.cancelFunc()

		require.True(t, connection.registerStream(&TestProtocol{}, stream))

		select {
		case <-connection.ctx.Done():
			t.Fatal("connection was closed without an idle timeout configured")
		case <-time.After(200 * time.Millisecond):
		}
		assert.True(t, connection.IsConnected())
	})
}
