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
	"crypto/tls"
	"fmt"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"google.golang.org/grpc"
	"sync"
	"sync/atomic"
)

// AnyProtocol is a constant for checking the connectivity on any supported protocol.
const AnyProtocol = "*"

// managedConnection is created by grpcConnectionManager to register a connection to a peer.
// The connection can be either inbound or outbound. The presence of a managedConnection for a peer doesn't imply
// there's an actual connection, because it might still be trying to establish an outbound connection to the given peer.
type managedConnection interface {
	// disconnect shuts down active inbound or outbound streams.
	disconnect()
	// close shuts down active inbound or outbound streams and stops active outbound connectors.
	// After calling close() the managedConnection cannot be reused.
	close()
	getPeer() transport.Peer
	connected(protocol string) bool
	// open instructs the managedConnection to start connecting to the remote peer (attempting an outbound connection).
	open(config *tls.Config, callback func(grpcConn *grpc.ClientConn))
	// registerClientStream adds the given grpc.ClientStream to this managedConnection. It is closed when close() is called.
	registerClientStream(stream grpc.ClientStream, method string) error
	// registerServerStream adds the given grpc.ServerStream to this managedConnection.
	registerServerStream(stream grpc.ServerStream) error
	// context returns the context that is cancelled when the connection is closed.
	context() context.Context
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
		grpcInboundStreams:           make(map[string]grpc.ServerStream),
		grpcOutboundStreams:          make(map[string]grpc.ClientStream),
	}
	result.peer.Store(peer)
	return result
}

type conn struct {
	peer                         atomic.Value
	ctx                          context.Context
	cancelCtx                    func()
	mux                          sync.RWMutex
	connector                    *outboundConnector
	grpcOutboundConnection       *grpc.ClientConn
	grpcOutboundStreams          map[string]grpc.ClientStream
	grpcInboundStreams           map[string]grpc.ServerStream
	inboundStreamsClosedCallback func(managedConnection)
	dialer                       dialer
}

func (mc *conn) getPeer() transport.Peer {
	// Populated through createConnection and verifyOrSetPeerID
	peer, _ := mc.peer.Load().(transport.Peer)
	return peer
}

func (mc *conn) disconnect() {
	mc.mux.Lock()
	defer mc.mux.Unlock()

	mc.doDisconnect()
}

func (mc *conn) close() {
	mc.mux.Lock()
	defer mc.mux.Unlock()

	if mc.connector != nil {
		mc.connector.stop()
		mc.connector = nil
	}

	mc.doDisconnect()

	mc.grpcInboundStreams = nil
	mc.grpcOutboundStreams = nil
	mc.cancelCtx = nil
	mc.ctx = nil
}

func (mc *conn) context() context.Context {
	mc.mux.RLock()
	defer mc.mux.RUnlock()
	return mc.ctx
}

func (mc *conn) doDisconnect() {
	if mc.cancelCtx != nil {
		mc.cancelCtx()
	}

	// Clean up incoming connections
	mc.grpcInboundStreams = make(map[string]grpc.ServerStream)

	// Clean up outbound connections
	mc.grpcOutboundStreams = make(map[string]grpc.ClientStream)
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

func (mc *conn) registerClientStream(clientStream grpc.ClientStream, method string) error {
	mc.mux.Lock()
	defer mc.mux.Unlock()

	if _, exists := mc.grpcOutboundStreams[method]; exists {
		return fmt.Errorf("peer is already connected (method=%s)", method)
	}

	// when the gRPC stream cancels, cancel the connection's context
	if mc.ctx == nil {
		mc.ctx, mc.cancelCtx = context.WithCancel(context.Background())
	}
	go func(cancel func()) {
		<-clientStream.Context().Done()
		cancel()
	}(mc.cancelCtx)

	mc.grpcOutboundStreams[method] = clientStream
	return nil
}

func (mc *conn) registerServerStream(serverStream grpc.ServerStream) error {
	mc.mux.Lock()
	defer mc.mux.Unlock()

	method := grpc.ServerTransportStreamFromContext(serverStream.Context()).Method()
	if _, exists := mc.grpcInboundStreams[method]; exists {
		return fmt.Errorf("peer is already connected (method=%s)", method)
	}
	if _, exists := mc.grpcOutboundStreams[method]; exists {
		return fmt.Errorf("peer is already connected (method=%s)", method)
	}

	mc.grpcInboundStreams[method] = serverStream

	// when the gRPC stream cancels, cancel the connection's context
	if mc.ctx == nil {
		mc.ctx, mc.cancelCtx = context.WithCancel(context.Background())
	}
	go func(cancel func()) {
		// Wait for the serverStream to close. Then remove it, and if it was the last one, callback
		<-serverStream.Context().Done()
		cancel()
		mc.mux.Lock()
		defer mc.mux.Unlock()
		// Remove this stream from the inbound stream registry
		delete(mc.grpcInboundStreams, method)
		// If empty, remove.
		if len(mc.grpcInboundStreams) == 0 {
			mc.inboundStreamsClosedCallback(mc)
		}
	}(mc.cancelCtx)
	return nil
}

func (mc *conn) open(tlsConfig *tls.Config, connectedCallback func(grpcConn *grpc.ClientConn)) {
	mc.mux.Lock()
	defer mc.mux.Unlock()

	if mc.connector != nil {
		// Already connecting
		return
	}

	mc.connector = createOutboundConnector(mc.getPeer().Address, mc.dialer, tlsConfig, func() bool {
		return !mc.connected(AnyProtocol)
	}, func(conn *grpc.ClientConn) {
		mc.mux.Lock()
		mc.grpcOutboundConnection = conn
		mc.mux.Unlock()

		connectedCallback(conn)
	})
	mc.connector.start()
}

func (mc *conn) connected(protocol string) bool {
	mc.mux.RLock()
	defer mc.mux.RUnlock()

	if protocol != AnyProtocol {
		// Check for specific protocol
		if mc.grpcOutboundStreams[protocol] != nil {
			return true
		}
		if mc.grpcInboundStreams[protocol] != nil {
			return true
		}
		return false
	}

	// Check on any protocol
	if len(mc.grpcOutboundStreams) > 0 {
		return true
	}
	if len(mc.grpcInboundStreams) > 0 {
		return true
	}
	return false
}
