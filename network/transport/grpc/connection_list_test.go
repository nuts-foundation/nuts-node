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
	"testing"
)

type stubPredicate struct {
	count int
}

func (p *stubPredicate) Match(_ Connection) bool {
	match := p.count == 0
	p.count--

	return match
}

func TestConnectionList_Get(t *testing.T) {
	conn1 := &StubConnection{Open: true}
	conn2 := &StubConnection{Open: false}
	cn := connectionList{
		list: []Connection{conn1, conn2},
	}

	assert.Equal(t, nil, cn.Get(&stubPredicate{count: 2}))
	assert.Equal(t, conn1, cn.Get(&stubPredicate{count: 0}))
	assert.Equal(t, conn2, cn.Get(&stubPredicate{count: 1}))
}

func TestConnectionList_All(t *testing.T) {
	cn := connectionList{}

	cn.getOrRegister(context.Background(), transport.Peer{ID: "a"}, false)
	cn.getOrRegister(context.Background(), transport.Peer{ID: "b"}, false)

	assert.Len(t, cn.All(), 2)
}

func TestConnectionList_getOrRegister(t *testing.T) {
	t.Run("second call with same peer ID should return same connection", func(t *testing.T) {
		cn := connectionList{}
		connA, created1 := cn.getOrRegister(context.Background(), transport.Peer{ID: "a"}, false)
		assert.True(t, created1)
		connASecondCall, created2 := cn.getOrRegister(context.Background(), transport.Peer{ID: "a"}, false)
		assert.False(t, created2)
		assert.Equal(t, connA, connASecondCall)
	})

	t.Run("second call with different Peer ID", func(t *testing.T) {
		peerA := transport.Peer{ID: "a", Address: "grpc://example.com"}
		peerB := transport.Peer{ID: "b"}
		peerC := transport.Peer{ID: "c", Address: "127.0.0.1"}
		peerD := transport.Peer{ID: "d", Address: "127.0.0.1"}

		t.Run("for incoming connections", func(t *testing.T) {
			t.Run("with different address returns new connection", func(t *testing.T) {
				cn := connectionList{}
				connA, created1 := cn.getOrRegister(context.Background(), peerA, false)
				assert.True(t, created1)
				connB, created2 := cn.getOrRegister(context.Background(), peerB, false)
				assert.True(t, created2)
				assert.NotEqual(t, connA, connB)
			})

			t.Run("with same address returns new connection", func(t *testing.T) {
				cn := connectionList{}
				connA, created1 := cn.getOrRegister(context.Background(), peerC, false)
				assert.True(t, created1)
				connB, created2 := cn.getOrRegister(context.Background(), peerD, false)
				assert.True(t, created2)
				assert.NotEqual(t, connA, connB)
			})
		})

		t.Run("for outgoing connections", func(t *testing.T) {
			t.Run("with different address returns new connection", func(t *testing.T) {
				cn := connectionList{}
				connA, created1 := cn.getOrRegister(context.Background(), peerA, true)
				assert.True(t, created1)
				connB, created2 := cn.getOrRegister(context.Background(), peerB, true)
				assert.True(t, created2)
				assert.NotEqual(t, connA, connB)
			})

			t.Run("with same address returns same connection", func(t *testing.T) {
				cn := connectionList{}
				connA, created1 := cn.getOrRegister(context.Background(), peerC, true)
				assert.True(t, created1)
				connB, created2 := cn.getOrRegister(context.Background(), peerD, true)
				assert.False(t, created2)
				assert.Equal(t, connA, connB)
			})
		})
	})
}

func TestConnectionList_remove(t *testing.T) {
	cn := connectionList{}
	connA, _ := cn.getOrRegister(context.Background(), transport.Peer{ID: "a"}, false)
	connB, _ := cn.getOrRegister(context.Background(), transport.Peer{ID: "b"}, false)
	connC, _ := cn.getOrRegister(context.Background(), transport.Peer{ID: "c"}, false)

	assert.Len(t, cn.list, 3)
	cn.remove(connB)
	assert.Len(t, cn.list, 2)
	assert.Contains(t, cn.list, connA)
	assert.Contains(t, cn.list, connC)
}

func TestConnectionList_Diagnostics(t *testing.T) {
	t.Run("no connections", func(t *testing.T) {
		cn := connectionList{}

		diagnostics := cn.Diagnostics()

		assert.Len(t, diagnostics, 2)
		idx := 0
		assert.Equal(t, 0, diagnostics[idx].(numberOfPeersStatistic).numberOfPeers)
		idx++
		assert.Empty(t, diagnostics[idx].(peersStatistic).peers)
	})
	t.Run("connections", func(t *testing.T) {
		stream := newServerStream("foo", "")
		defer stream.cancelFunc()
		cn := connectionList{}
		// 2 connections: 1 disconnected, 1 connected, 1 trying to connect outbound
		connectionB, _ := cn.getOrRegister(context.Background(), transport.Peer{ID: "b"}, false) // simulate inactive connection
		_ = connectionB
		connectionC, _ := cn.getOrRegister(context.Background(), transport.Peer{ID: "c", Address: "localhost:5555"}, false)
		assert.True(t, connectionC.registerStream(&TestProtocol{}, stream)) // simulate active connection

		diagnostics := cn.Diagnostics()

		assert.Len(t, diagnostics, 2)
		idx := 0
		assert.Equal(t, 1, diagnostics[idx].(numberOfPeersStatistic).numberOfPeers)
		idx++
		assert.Len(t, diagnostics[idx].(peersStatistic).peers, 1)
	})
}
