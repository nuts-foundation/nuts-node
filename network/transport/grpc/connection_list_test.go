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
	"testing"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/stretchr/testify/assert"
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

func TestConnectionList_getOrRegister1(t *testing.T) {
	t.Run("anonymous", func(t *testing.T) {
		anon1ID1 := transport.Peer{ID: "peer1", Address: "address1"}
		anon1ID2 := transport.Peer{ID: "peer2", Address: "address1"}
		anon2ID2 := transport.Peer{ID: "peer2", Address: "address2"}
		t.Run("inbound", func(t *testing.T) {
			cn := connectionList{}
			// accepted x2
			_, created := cn.getOrRegister(context.Background(), anon1ID1, false)
			assert.True(t, created)
			conn2, created := cn.getOrRegister(context.Background(), anon1ID2, false)
			assert.True(t, created)
			assert.Len(t, cn.list, 2)

			// already exist, duplicate on peerID and empty DID
			conn3, created := cn.getOrRegister(context.Background(), anon2ID2, false)
			assert.False(t, created)
			assert.Len(t, cn.list, 2)
			assert.Equal(t, conn2, conn3)
		})
		t.Run("outbound", func(t *testing.T) {
			cn := connectionList{}
			// accepted x2
			conn1, created := cn.getOrRegister(context.Background(), anon1ID1, true)
			assert.True(t, created)
			_, created = cn.getOrRegister(context.Background(), anon2ID2, true)
			assert.True(t, created)
			assert.Len(t, cn.list, 2)

			// already exist, duplicate on address and empty DID
			conn3, created := cn.getOrRegister(context.Background(), anon1ID2, true)
			assert.False(t, created)
			assert.Len(t, cn.list, 2)
			assert.Equal(t, conn1, conn3)
		})
	})
	t.Run("with DID", func(t *testing.T) {
		peer1ID1 := transport.Peer{ID: "peer1", Address: "address1", NodeDID: did.MustParseDID("did:nuts:peer1")}
		peer1ID2 := transport.Peer{ID: "peer2", Address: "address1", NodeDID: did.MustParseDID("did:nuts:peer1")}
		peer2ID2 := transport.Peer{ID: "peer2", Address: "address2", NodeDID: did.MustParseDID("did:nuts:peer2")}

		t.Run("inbound", func(t *testing.T) {
			cn := connectionList{}
			// accepted x2
			conn1, created := cn.getOrRegister(context.Background(), peer1ID1, false)
			assert.True(t, created)
			// second peerID for same DID
			_, created = cn.getOrRegister(context.Background(), peer1ID2, false)
			assert.True(t, created)
			assert.Len(t, cn.list, 2)

			// already exist, duplicate on peerID and empty DID
			conn3, created := cn.getOrRegister(context.Background(), peer1ID1, false)
			assert.False(t, created)
			assert.Len(t, cn.list, 2)
			assert.Equal(t, conn1, conn3)

		})
		t.Run("outbound", func(t *testing.T) {
			cn := connectionList{}
			// accepted x2
			conn1, created := cn.getOrRegister(context.Background(), peer1ID1, true)
			assert.True(t, created)
			_, created = cn.getOrRegister(context.Background(), peer2ID2, true)
			assert.True(t, created)
			assert.Len(t, cn.list, 2)

			// already exist, duplicate on address and empty DID
			conn3, created := cn.getOrRegister(context.Background(), peer1ID2, true)
			assert.False(t, created)
			assert.Len(t, cn.list, 2)
			assert.Equal(t, conn1, conn3)
		})
	})
	t.Run("allow anon + authenticated at same time", func(t *testing.T) {
		cn := connectionList{}
		for i := 0; i < 2; i++ {
			// first three are accepted on the first iteration
			cn.getOrRegister(context.Background(), transport.Peer{ID: "peer", Address: "some-ip"}, false)                                             // anonymous inbound
			cn.getOrRegister(context.Background(), transport.Peer{ID: "peer", Address: "some-ip", NodeDID: did.MustParseDID("did:nuts:peer")}, false) // did inbound
			cn.getOrRegister(context.Background(), transport.Peer{ID: "peer", Address: "address"}, true)                                              // bootstrap outbound
			// duplicate based on DID
			_, created := cn.getOrRegister(context.Background(), transport.Peer{ID: "peer", Address: "address", NodeDID: did.MustParseDID("did:nuts:peer")}, true) // did outbound
			assert.False(t, created)
		}
		assert.Len(t, cn.list, 3)
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
