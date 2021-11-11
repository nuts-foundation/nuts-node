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

// managedConnection is created by grpcConnectionManager to register a connection to a peer.
// The connection can be either inbound or outbound. The presence of a managedConnection for a peer doesn't imply
// there's an actual connection, because it might still be trying to establish an outbound connection to the given peer.
type managedConnection interface {
	// close shuts down active inbound or outbound streams and stops active outbound connectors.
	close()
	getPeer() transport.Peer
	connected(protocol string) bool
	// open instructs the managedConnection to start connecting to the remote peer (attempting an outbound connection).
	open(config *tls.Config, callback func(grpcConn *grpc.ClientConn))
	// registerClientStream adds the given grpc.ClientStream to this managedConnection. It is closed when close() is called.
	registerClientStream(stream grpc.ClientStream)
	// registerServerStream adds the given grpc.ServerStream to this managedConnection.
	registerServerStream(stream grpc.ServerStream)
	// closer returns a channel that receives an item when the managedConnection is closing.
	// Each time it is called a new channel will be returned. All channels will be published to when it is closing.
	closer() <-chan struct{}
	// verifyOrSetPeerID checks whether the given transport.PeerID matches the one currently set for this connection.
	// If no transport.PeerID is set on this connection it just sets it. Subsequent calls must then match it.
	// This method is used to:
	// - Initial discovery of the peer's transport.PeerID, setting it when it isn't known before connecting.
	// - Verify multiple active protocols to the same peer all send the same transport.PeerID.
	// It returns false if the given transport.PeerID doesn't match the previously set transport.PeerID.
	verifyOrSetPeerID(id transport.PeerID) bool
}

func createConnection(dialer dialer, peer transport.Peer, inboundStreamsClosedCallback func(managedConnection)) managedConnection {
	result := &conn{
		dialer:                       dialer,
		inboundStreamsClosedCallback: inboundStreamsClosedCallback,
	}
	result.peer.Store(peer)
	return result
}

type conn struct {
	peer                         atomic.Value
	closers                      []chan struct{}
	mux                          sync.Mutex
	connector                    *outboundConnector
	grpcOutboundConnection       *grpc.ClientConn
	grpcOutboundStreams          []grpc.ClientStream
	grpcInboundStreams           []grpc.ServerStream
	inboundStreamsClosedCallback func(managedConnection)
	dialer                       dialer
}

func (mc *conn) getPeer() transport.Peer {
	// Populated through createConnection and verifyOrSetPeerID
	peer, _ := mc.peer.Load().(transport.Peer)
	return peer
}

func (mc *conn) closer() <-chan struct{} {
	mc.mux.Lock()
	defer mc.mux.Unlock()
	closer := make(chan struct{}, 1)
	mc.closers = append(mc.closers, closer)
	return closer
}

func (mc *conn) close() {
	mc.mux.Lock()
	defer mc.mux.Unlock()

	for _, closer := range mc.closers {
		if len(closer) == 0 { // make sure we don't block should this function be called twice
			closer <- struct{}{}
		}
	}

	mc.grpcOutboundStreams = nil
	mc.grpcInboundStreams = nil

	// Close the grpc.ClientConn (outbound connection)
	if mc.grpcOutboundConnection != nil {
		_ = mc.grpcOutboundConnection.Close()
		mc.grpcOutboundConnection = nil
	}
}

func (mc *conn) verifyOrSetPeerID(id transport.PeerID) bool {
	mc.mux.Lock()
	defer mc.mux.Unlock()
	currentPeer := mc.getPeer()
	if len(currentPeer.ID) == 0 {
		currentPeer.ID = id
		mc.peer.Store(currentPeer)
		return true
	}
	return currentPeer.ID == id
}

func (mc *conn) registerClientStream(clientStream grpc.ClientStream) {
	mc.mux.Lock()
	defer mc.mux.Unlock()
	mc.grpcOutboundStreams = append(mc.grpcOutboundStreams, clientStream)
}

func (mc *conn) registerServerStream(serverStream grpc.ServerStream) {
	mc.mux.Lock()
	defer mc.mux.Unlock()
	mc.grpcInboundStreams = append(mc.grpcInboundStreams, serverStream)

	go func() {
		// Wait for the serverStream to close. Then remove it, and if it was the last one, callback
		<-serverStream.Context().Done()
		mc.mux.Lock()
		defer mc.mux.Unlock()
		// Remove this stream from the inbound stream list
		var j int
		for _, curr := range mc.grpcInboundStreams {
			if curr != serverStream {
				mc.grpcInboundStreams[j] = curr
				j++
			}
		}
		mc.grpcInboundStreams = mc.grpcInboundStreams[:j]
		// If empty, remove.
		if len(mc.grpcInboundStreams) == 0 {
			mc.inboundStreamsClosedCallback(mc)
		}
	}()
}

func (mc *conn) open(tlsConfig *tls.Config, connectedCallback func(grpcConn *grpc.ClientConn)) {
	mc.mux.Lock()
	defer mc.mux.Unlock()

	if mc.connector != nil {
		// Already connecting
		return
	}

	mc.closers = nil

	mc.connector = createOutboundConnector(mc.getPeer().Address, mc.dialer, tlsConfig, func() bool {
		return !mc.connected("")
	}, func(conn *grpc.ClientConn) {
		mc.mux.Lock()
		mc.grpcOutboundConnection = conn
		mc.mux.Unlock()

		connectedCallback(conn)
	})
	go mc.connector.loopConnect()
}

func (mc *conn) connected(protocol string) bool {
	mc.mux.Lock()
	defer mc.mux.Unlock()

	// TODO: Check protocol
	if len(mc.grpcOutboundStreams) > 0 {
		return true
	}
	if len(mc.grpcInboundStreams) > 0 {
		return true
	}
	return false
}
