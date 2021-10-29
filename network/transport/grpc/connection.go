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
	"crypto/tls"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"google.golang.org/grpc"
	"sync"
	"sync/atomic"
)

type managedConnection struct {
	peer                   atomic.Value
	closers                []chan struct{}
	mux                    sync.Mutex
	connector              *outboundConnector
	grpcOutboundConnection *grpc.ClientConn
	grpcOutboundStreams    []grpc.ClientStream
	grpcInboundStreams     []grpc.ServerStream
	dialer                 dialer
}

func (mc *managedConnection) getPeer() transport.Peer {
	peer, _ := mc.peer.Load().(transport.Peer)
	return peer
}

func (mc *managedConnection) setPeer(value transport.Peer) {
	mc.peer.Store(value)
}

func (mc *managedConnection) closer() chan struct{} {
	mc.mux.Lock()
	defer mc.mux.Unlock()
	closer := make(chan struct{}, 1)
	mc.closers = append(mc.closers, closer)
	return closer
}

func (mc *managedConnection) close() {
	mc.mux.Lock()
	defer mc.mux.Unlock()

	for _, closer := range mc.closers {
		if len(closer) == 0 { // make sure we don't block should this function be called twice
			closer <- struct{}{}
		}
	}
	// TODO: Should we wait until the closer channels have been drained?

	mc.grpcOutboundStreams = nil
	mc.grpcInboundStreams = nil

	// Close the grpc.ClientConn (outbound connection)
	if mc.grpcOutboundConnection != nil {
		_ = mc.grpcOutboundConnection.Close()
		mc.grpcOutboundConnection = nil
	}
}

// verifyOrSetPeerID checks whether the given transport.PeerID matches the one currently set for this connection.
// If no transport.PeerID is set on this connection it just sets it. Subsequent calls must then match it.
// This method is used to:
// - Initial discovery of the peer's transport.PeerID, setting it when it isn't known before connecting.
// - Verify multiple active protocols to the same peer all send the same transport.PeerID.
// It returns false if the given transport.PeerID doesn't match the previously set transport.PeerID.
func (mc *managedConnection) verifyOrSetPeerID(id transport.PeerID) bool {
	mc.mux.Lock()
	defer mc.mux.Unlock()
	currentPeer := mc.getPeer()
	if len(currentPeer.ID) == 0 {
		currentPeer.ID = id
		mc.setPeer(currentPeer)
		return true
	}
	return currentPeer.ID == id
}

// registerClientStream adds the given grpc.ClientStream to this managedConnection. It is closed when close() is called.
func (mc *managedConnection) registerClientStream(clientStream grpc.ClientStream) {
	mc.mux.Lock()
	defer mc.mux.Unlock()
	mc.grpcOutboundStreams = append(mc.grpcOutboundStreams, clientStream)
}

// registerServerStream adds the given grpc.ServerStream to this managedConnection.
func (mc *managedConnection) registerServerStream(serverStream grpc.ServerStream) {
	mc.mux.Lock()
	defer mc.mux.Unlock()
	mc.grpcInboundStreams = append(mc.grpcInboundStreams, serverStream)
}

// open instructs the managedConnection to start connecting to the remote peer (attempting an outbound connection).
func (mc *managedConnection) open(tlsConfig *tls.Config, connectedCallback func(grpcConn *grpc.ClientConn)) {
	mc.mux.Lock()
	defer mc.mux.Unlock()

	if mc.connector != nil {
		// Already connecting
		return
	}

	mc.closers = nil

	mc.connector = &outboundConnector{
		address:   mc.getPeer().Address,
		dialer:    mc.dialer,
		tlsConfig: tlsConfig,
		connectedCallback: func(conn *grpc.ClientConn) {
			mc.mux.Lock()
			mc.grpcOutboundConnection = conn
			mc.mux.Unlock()

			connectedCallback(conn)
		},
	}
	go mc.connector.loopConnect()
}

func (mc *managedConnection) connected() bool {
	mc.mux.Lock()
	defer mc.mux.Unlock()

	if len(mc.grpcOutboundStreams) > 0 {
		return true
	}
	if len(mc.grpcInboundStreams) > 0 {
		return true
	}
	return false
}

func (c *connectionList) remove(target *managedConnection) {
	c.mux.Lock()
	defer c.mux.Unlock()

	var j int
	for _, curr := range c.list {
		if curr != target {
			c.list[j] = curr
			j++
		}
	}
	c.list = c.list[:j]
}
