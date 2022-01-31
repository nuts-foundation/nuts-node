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
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Connection is created by grpcConnectionManager to register a connection to a peer.
// The connection can be either inbound or outbound. The presence of a Connection for a peer doesn't imply
// there's an actual connection, because it might still be trying to establish an outbound connection to the given peer.
type Connection interface {
	// disconnect shuts down active inbound or outbound streams.
	disconnect()
	// waitUntilDisconnected blocks until the connection is closed. If it already is closed or was never open, it returns immediately.
	waitUntilDisconnected()
	// startConnecting instructs the Connection to start connecting to the remote peer (attempting an outbound connection).
	startConnecting(address string, config *tls.Config, callback func(grpcConn *grpc.ClientConn) bool)
	// stopConnecting instructs the Connection to stop connecting to the remote peer.
	stopConnecting()

	// registerClientStream adds the given grpc.ClientStream to this Connection under the given method,
	// which holds the fully qualified name of the gRPC stream call. It can be formatted using grpc.GetStreamMethod
	// (the gRPC library does not provide it for grpc.ClientStream, like it does for server grpc.ServerStream).
	// The stream is closed when close() is called.
	registerStream(protocol Protocol, stream Stream) bool

	// Send tries to send the given message over the stream of the given protocol.
	// If there's no active stream for the protocol, or something else goes wrong, an error is returned.
	Send(protocol Protocol, envelope interface{}) error

	// setPeer sets the peer of this connection.
	setPeer(peer transport.Peer)

	// verifyOrSetPeerID checks whether the given transport.PeerID matches the one currently set for this connection.
	// If no transport.PeerID is set on this connection it just sets it. Subsequent calls must then match it.
	// This method is used to:
	// - Initial discovery of the peer's transport.PeerID, setting it when it isn't known before connecting.
	// - Verify multiple active protocols to the same peer all send the same transport.PeerID.
	// It returns false if the given transport.PeerID doesn't match the previously set transport.PeerID.
	verifyOrSetPeerID(id transport.PeerID) bool

	// stats returns statistics for this connection
	outboundConnector() *outboundConnector

	// Peer returns the associated peer information of this connection. If the connection is not active, it will return an empty peer.
	Peer() transport.Peer

	// IsConnected returns whether the connection is active or not.
	IsConnected() bool
}

func createConnection(parentCtx context.Context, dialer dialer, peer transport.Peer) Connection {
	result := &conn{
		dialer:    dialer,
		streams:   make(map[string]Stream),
		outboxes:  make(map[string]chan interface{}),
		parentCtx: parentCtx,
	}
	result.peer.Store(peer)
	return result
}

type conn struct {
	peer      atomic.Value
	ctx       context.Context
	cancelCtx func()
	mux       sync.RWMutex
	connector *outboundConnector
	streams   map[string]Stream
	outboxes  map[string]chan interface{}

	dialer    dialer
	parentCtx context.Context
}

func (mc *conn) Peer() transport.Peer {
	// Populated through createConnection and verifyOrSetPeerID
	peer, _ := mc.peer.Load().(transport.Peer)
	return peer
}

func (mc *conn) disconnect() {
	mc.mux.Lock()
	defer mc.mux.Unlock()

	if mc.ctx == nil {
		// Not connected
		return
	}

	mc.cancelCtx()
	mc.ctx = nil

	// Close streams
	mc.streams = make(map[string]Stream)

	// Close outboxes
	for _, outbox := range mc.outboxes {
		close(outbox)
	}
	mc.outboxes = make(map[string]chan interface{})

	// Reset peer ID, since when it reconnects it might have changed (due to a reboot)
	mc.peer.Store(transport.Peer{})
}

func (mc *conn) waitUntilDisconnected() {
	mc.mux.RLock()
	var done <-chan struct{}
	if mc.ctx != nil {
		done = mc.ctx.Done()
	}
	mc.mux.RUnlock()
	if done != nil {
		<-done
	}
}

func (mc *conn) verifyOrSetPeerID(id transport.PeerID) bool {
	mc.mux.Lock()
	defer mc.mux.Unlock()
	currentPeer := mc.Peer()
	if len(currentPeer.ID) == 0 {
		currentPeer.ID = id
		mc.peer.Store(currentPeer)
		return true
	}
	return currentPeer.ID == id
}

func (mc *conn) setPeer(peer transport.Peer) {
	mc.peer.Store(peer)
}

func (mc *conn) Send(protocol Protocol, envelope interface{}) error {
	mc.mux.Lock()
	defer mc.mux.Unlock()

	outbox := mc.outboxes[protocol.MethodName()]
	if outbox == nil {
		return fmt.Errorf("can't send message, protocol not connected: %s", protocol.MethodName())
	}
	if len(outbox) >= cap(outbox) {
		// This node is a slow responder, we'll have to drop this message because our backlog is full.
		return fmt.Errorf("peer's outbound message backlog has reached max capacity, message is dropped (peer=%s,backlog-size=%d)", mc.Peer(), cap(outbox))
	}
	outbox <- envelope

	return nil
}

func (mc *conn) registerStream(protocol Protocol, stream Stream) bool {
	mc.mux.Lock()
	defer mc.mux.Unlock()

	methodName := protocol.MethodName()
	if mc.streams[methodName] != nil {
		return false
	}

	if mc.ctx == nil {
		mc.ctx, mc.cancelCtx = context.WithCancel(mc.parentCtx)
	}

	mc.streams[methodName] = stream
	mc.outboxes[methodName] = make(chan interface{}, 20)

	mc.startReceiving(protocol, stream)
	mc.startSending(protocol, stream)

	// A connection can have multiple active streams, but if one of them is closed, all of them should be closed, also closing the underlying connection.
	go func(cancel func()) {
		<-stream.Context().Done()
		cancel()
	}(mc.cancelCtx)

	return true
}

func (mc *conn) startReceiving(protocol Protocol, stream Stream) {
	peer := mc.Peer() // copy Peer, because it will be nil when logging after disconnecting.
	go func() {
		for {
			message := protocol.CreateEnvelope()
			err := stream.RecvMsg(message)
			if err != nil {
				errStatus, isStatusError := status.FromError(err)
				if errors.Is(err, io.EOF) || (isStatusError && errStatus.Code() == codes.Canceled) {
					log.Logger().Infof("%s: Peer closed connection (peer=%s)", protocol.MethodName(), peer)
				} else {
					log.Logger().Warnf("%s: Peer connection error (peer=%s): %v", protocol.MethodName(), peer, err)
				}
				mc.mux.Lock()
				mc.cancelCtx()
				mc.mux.Unlock()
				break
			}

			err = protocol.Handle(peer, message)
			if err != nil {
				log.Logger().Warnf("%s: Error handling message %T (peer=%s): %v", protocol.MethodName(), protocol.UnwrapMessage(message), peer, err)
			}
		}
	}()
}

func (mc *conn) startSending(protocol Protocol, stream Stream) {
	outbox := mc.outboxes[protocol.MethodName()]
	done := mc.ctx.Done()

	go func() {
	loop:
		for {
			select {
			case _ = <-done:
				break loop
			case envelope := <-outbox:
				err := stream.SendMsg(envelope)
				if err != nil {
					log.Logger().Warnf("Unable to send message %T, message is dropped (peer=%s): %v", envelope, mc.Peer(), err)
				}
			}
		}
		// Connection closed, see if we need to close the gRPC stream
		clientStream, ok := stream.(grpc.ClientStream)
		if ok {
			err := clientStream.CloseSend()
			if err != nil {
				log.Logger().Warnf("Error while closing client for gRPC stream %s: %v", protocol.MethodName(), err)
			}
		}
	}()
}

func (mc *conn) startConnecting(address string, tlsConfig *tls.Config, connectedCallback func(grpcConn *grpc.ClientConn) bool) {
	mc.mux.Lock()
	defer mc.mux.Unlock()

	if mc.connector != nil {
		// Already connecting
		return
	}

	mc.connector = createOutboundConnector(address, mc.dialer, tlsConfig, func() bool {
		return !mc.IsConnected()
	}, connectedCallback)
	mc.connector.start()
}

func (mc *conn) stopConnecting() {
	mc.mux.Lock()
	defer mc.mux.Unlock()

	if mc.connector == nil {
		// Not connecting
		return
	}

	mc.connector.stop()
	mc.connector = nil
}

func (mc *conn) IsConnected() bool {
	mc.mux.RLock()
	defer mc.mux.RUnlock()

	return mc.ctx != nil
}

func (mc *conn) outboundConnector() *outboundConnector {
	mc.mux.RLock()
	defer mc.mux.RUnlock()

	return mc.connector
}
