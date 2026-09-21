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
	"errors"
	"fmt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/v6/core"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nuts-foundation/nuts-node/v6/network/log"
	"github.com/nuts-foundation/nuts-node/v6/network/transport"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// OutboxHardLimit defines how many outgoing messages may be queued per protocol
// this is the hard limit of the underlying channel
const OutboxHardLimit = 5000

// outboxSoftLimit defines how many outgoing messages are desirable to be queued per protocol
// If needed the channel may grow to OutboxHardLimit
const outboxSoftLimit = 100

// Connection is created by grpcConnectionManager to register a connection to a peer.
// The connection can be either inbound or outbound. The presence of a Connection for a peer doesn't imply
// there's an actual connection, because it might still be trying to establish an outbound connection to the given peer.
type Connection interface {
	// disconnect shuts down active inbound or outbound streams.
	disconnect()
	// waitUntilDisconnected blocks until the connection is closed. If it already is closed or was never open, it returns immediately.
	waitUntilDisconnected()

	// registerClientStream adds the given grpc.ClientStream to this Connection under the given method,
	// which holds the fully qualified name of the gRPC stream call. It can be formatted using grpc.GetStreamMethod
	// (the gRPC library does not provide it for grpc.ClientStream, like it does for server grpc.ServerStream).
	// The stream is closed when close() is called.
	registerStream(protocol Protocol, stream Stream) bool

	// Send tries to send the given message over the stream of the given protocol.
	// If there's no active stream for the protocol, or something else goes wrong, an error is returned.
	// A sender may specify ignoreSoftLimit=true to allow extra messages to be sent.
	// This is needed to finish sending a TransactionList that falls within a single page.
	Send(protocol Protocol, envelope interface{}, ignoreSoftLimit bool) error

	// setPeer sets the peer of this connection.
	setPeer(peer transport.Peer)

	// verifyOrSetPeerID checks whether the given transport.PeerID matches the one currently set for this connection.
	// If no transport.PeerID is set on this connection it just sets it. Subsequent calls must then match it.
	// This method is used to:
	// - Initial discovery of the peer's transport.PeerID, setting it when it isn't known before connecting.
	// - Verify multiple active protocols to the same peer all send the same transport.PeerID.
	// It returns false if the given transport.PeerID doesn't match the previously set transport.PeerID.
	verifyOrSetPeerID(id transport.PeerID) bool

	// Peer returns the associated peer information of this connection.
	Peer() transport.Peer

	// IsConnected returns whether the connection is active or not.
	IsConnected() bool

	// IsAuthenticated returns whether teh given connection is authenticated.
	IsAuthenticated() bool

	// closeError returns the status when the connection closed with an error or nil otherwise
	closeError() *status.Status
	// waitForReceivers blocks until all receive loops have exited, which makes closeError() final.
	// The underlying streams must be closed first, otherwise the receive loops keep blocking on RecvMsg.
	waitForReceivers()
}

func createConnection(parentCtx context.Context, peer transport.Peer, idleTimeout time.Duration) Connection {
	result := &conn{
		streams:     make(map[string]Stream),
		outboxes:    make(map[string]chan interface{}),
		idleTimeout: idleTimeout,
	}
	result.ctx, result.cancelCtx = context.WithCancel(parentCtx)
	result.setPeer(peer)
	return result
}

type conn struct {
	peer atomic.Value
	// idleTimeout is the period without any received message after which the connection is closed. Zero disables the check.
	idleTimeout time.Duration
	// lastReceived holds the time a message was last received on any of the connection's streams.
	lastReceived atomic.Value
	// handling counts the receive loops that are currently handling a message; the idle timeout does not apply while handling.
	handling atomic.Int32
	// receivers tracks the receive loops only, so waitForReceivers can block until the close status is final.
	// A WaitGroup is needed because only the receive loops write the close status, and a connection can have
	// several of them, one per protocol stream.
	receivers sync.WaitGroup
	ctx       context.Context
	cancelCtx func()
	status    atomic.Pointer[status.Status]
	mux       sync.RWMutex
	streams   map[string]Stream
	outboxes  map[string]chan interface{}
	// activeGoroutines counts every goroutine started for this connection: the receive loops, the send loops and
	// the idle watcher. It exists for the goroutine leak check in the tests, which asserts on the number.
	//
	// It cannot replace receivers above and receivers cannot replace it: a WaitGroup can be waited on but its
	// value cannot be read, an atomic counter can be read but cannot be waited on. Neither is a substitute for
	// the other, which is why the connection keeps both. Waiting on all goroutines instead of the receive loops
	// would also be wrong: startSending can block in SendMsg for as long as the gRPC transport takes to give up
	// on a dead connection, which has nothing to do with the close status.
	//
	// Both are maintained by startGoroutine and startReceiveLoop, so no caller has to remember to do it.
	activeGoroutines int32
}

func (mc *conn) Peer() transport.Peer {
	// Populated through createConnection and verifyOrSetPeerID
	peer, _ := mc.peer.Load().(transport.Peer)
	return peer
}

func (mc *conn) ID() transport.PeerID {
	return mc.Peer().ID
}

func (mc *conn) disconnect() {
	mc.mux.Lock()
	defer mc.mux.Unlock()

	mc.cancelCtx()

	// Close streams
	mc.streams = make(map[string]Stream)

	// Close outboxes
	for _, outbox := range mc.outboxes {
		close(outbox)
	}
	mc.outboxes = make(map[string]chan interface{})

	// Set peer ID, since when it reconnects it might have changed (due to a reboot). Also reset node DID because it has to be re-authenticated.
	peer := mc.Peer()
	peer.ID = ""
	peer.NodeDID = did.DID{}
	peer.Authenticated = false
	mc.setPeer(peer)
}

func (mc *conn) waitUntilDisconnected() {
	mc.mux.RLock()
	if len(mc.streams) == 0 {
		// do not wait if there is no connection
		mc.mux.RUnlock()
		return
	}
	mc.mux.RUnlock()
	<-mc.ctx.Done()
}

func (mc *conn) verifyOrSetPeerID(id transport.PeerID) bool {
	mc.mux.Lock()
	defer mc.mux.Unlock()
	currentPeer := mc.Peer()
	if len(currentPeer.ID) == 0 {
		currentPeer.ID = id
		mc.setPeer(currentPeer)
		return true
	}
	return currentPeer.ID == id
}

func (mc *conn) setPeer(peer transport.Peer) {
	mc.peer.Store(peer)
}

func (mc *conn) Send(protocol Protocol, envelope interface{}, ignoreSoftLimit bool) error {
	mc.mux.Lock()
	defer mc.mux.Unlock()

	outbox := mc.outboxes[protocol.MethodName()]
	if outbox == nil {
		return fmt.Errorf("can't send message, protocol not connected: %s", protocol.MethodName())
	}

	if len(outbox) >= cap(outbox) {
		// This node is a slow responder, we'll have to drop this message because our backlog is full.
		return fmt.Errorf("peer's outbound message backlog has reached hard limit, message is dropped (peer=%s,backlog-size=%d)", mc.Peer(), cap(outbox))
	}
	if len(outbox) >= outboxSoftLimit && !ignoreSoftLimit {
		return fmt.Errorf("peer's outbound message backlog has reached max desired capacity, message is dropped (peer=%s,backlog-size=%d)", mc.Peer(), outboxSoftLimit)
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

	if len(mc.streams) == 0 && mc.idleTimeout > 0 {
		// first stream on this connection: start watching for idleness
		mc.lastReceived.Store(time.Now())
		mc.watchIdle()
	}
	mc.streams[methodName] = stream
	mc.outboxes[methodName] = make(chan interface{}, OutboxHardLimit)

	mc.startReceiving(protocol, stream)
	mc.startSending(protocol, stream)

	// A connection can have multiple active streams, but if one of them is closed, all of them should be closed, also closing the underlying connection.
	go func() {
		<-stream.Context().Done()
		mc.cancelCtx()
	}()

	return true
}

// startGoroutine runs fn in a goroutine that is counted in activeGoroutines for as long as it runs.
func (mc *conn) startGoroutine(fn func()) {
	atomic.AddInt32(&mc.activeGoroutines, 1)
	go func() {
		defer atomic.AddInt32(&mc.activeGoroutines, -1)
		fn()
	}()
}

// startReceiveLoop runs a receive loop. On top of the counting done by startGoroutine it registers the loop with
// receivers, so waitForReceivers blocks until it has exited. Receive loops must be started through this function
// and not through startGoroutine, otherwise the close status can be read before it is written.
func (mc *conn) startReceiveLoop(fn func()) {
	mc.receivers.Add(1)
	mc.startGoroutine(func() {
		defer mc.receivers.Done()
		fn()
	})
}

// goroutineCount returns how many goroutines are currently running for this connection.
func (mc *conn) goroutineCount() int32 {
	return atomic.LoadInt32(&mc.activeGoroutines)
}

func (mc *conn) startReceiving(protocol Protocol, stream Stream) {
	peer := mc.Peer() // copy Peer, because it will be nil when logging after disconnecting.
	mc.startReceiveLoop(func() {
		for {
			message := protocol.CreateEnvelope()
			err := stream.RecvMsg(message) // blocking
			if err != nil {
				errStatus, isStatusError := status.FromError(err)
				closedWithError := !errors.Is(err, io.EOF) && !(isStatusError && errStatus.Code() == codes.Canceled)
				if mc.ctx.Err() == nil {
					// only log when the connection wasn't closed locally
					switch {
					case !closedWithError:
						log.Logger().
							WithField(core.LogFieldProtocolVersion, protocol.Version()).
							WithFields(peer.ToFields()).
							Debug("Peer closed connection")
					case isPeerRejection(errStatus):
						// The dialer reports a rejection once it knows how long it will back off,
						// see grpcConnectionManager.recordFailure. Logging it here as well would repeat it on every retry.
						log.Logger().
							WithError(err).
							WithField(core.LogFieldProtocolVersion, protocol.Version()).
							WithFields(peer.ToFields()).
							Debug("Peer rejected the connection")
					default:
						log.Logger().
							WithError(err).
							WithField(core.LogFieldProtocolVersion, protocol.Version()).
							WithFields(peer.ToFields()).
							Warn("Peer connection error")
					}
				}
				if closedWithError {
					// Record the peer's close status even if the connection was already cancelled (e.g. because the
					// stream's context is done), so the caller can decide whether the peer rejected the connection.
					mc.status.Store(errStatus)
				}
				mc.cancelCtx()
				break
			}
			if mc.ctx.Err() != nil {
				// connection has been closed: drop message and stop receiving
				return
			}
			mc.lastReceived.Store(time.Now())

			mc.handling.Add(1)
			err = protocol.Handle(mc, message)
			mc.handling.Add(-1)
			mc.lastReceived.Store(time.Now()) // handling a message counts as activity as well
			if err != nil {
				log.Logger().
					WithError(err).
					WithField(core.LogFieldProtocolVersion, protocol.Version()).
					WithFields(peer.ToFields()).
					WithField(core.LogFieldMessageType, fmt.Sprintf("%T", protocol.UnwrapMessage(message))).
					Warn("Error handling message")
			}
		}
	})
}

// watchIdle disconnects the connection when no message has been received within idleTimeout.
// Peers send gossip and diagnostics messages at a fixed interval, so a silent stream is a dead one
// (e.g. a half-open TCP connection or a proxy that kept the stream open after the other side went away).
func (mc *conn) watchIdle() {
	peer := mc.Peer() // copy Peer, because it will be reset by disconnect()
	mc.startGoroutine(func() {
		timer := time.NewTimer(mc.idleTimeout)
		defer timer.Stop()
		for {
			select {
			case <-mc.ctx.Done():
				return
			case <-timer.C:
				if mc.handling.Load() > 0 {
					// still busy handling a message (e.g. a large transaction list during sync), which is not idle
					timer.Reset(mc.idleTimeout)
					continue
				}
				lastReceived, _ := mc.lastReceived.Load().(time.Time)
				idle := time.Since(lastReceived)
				if idle < mc.idleTimeout {
					timer.Reset(mc.idleTimeout - idle)
					continue
				}
				log.Logger().
					WithFields(peer.ToFields()).
					WithField("idle", idle.Round(time.Second)).
					Warn("No messages received from peer within idle timeout, disconnecting")
				mc.disconnect()
				return
			}
		}
	})
}

func (mc *conn) startSending(protocol Protocol, stream Stream) {
	outbox := mc.outboxes[protocol.MethodName()]

	mc.startGoroutine(func() {
	loop:
		for {
			select {
			case <-mc.ctx.Done():
				break loop
			case envelope := <-outbox:
				if envelope == nil {
					// https://github.com/nuts-foundation/nuts-node/issues/1017
					// message to send can also be nil when the connection is closed,
					// and the outbox channel case receives the nil value before the done channel case receives its value.
					// This sometimes triggered a panic during test teardown on slow systems
					break loop
				}

				err := stream.SendMsg(envelope)
				if err != nil {
					log.Logger().
						WithError(err).
						WithField(core.LogFieldProtocolVersion, protocol.Version()).
						WithFields(mc.Peer().ToFields()).
						WithField(core.LogFieldMessageType, fmt.Sprintf("%T", envelope)).
						Warn("Unable to send message, message is dropped")
				}
			}
		}
		// Connection closed, see if we need to close the gRPC stream
		unwrappedStream := stream
		if unwrappable, ok := stream.(interface{ Unwrap() Stream }); ok {
			unwrappedStream = unwrappable.Unwrap()
		}
		clientStream, ok := unwrappedStream.(grpc.ClientStream)
		if ok {
			err := clientStream.CloseSend()
			if err != nil {
				log.Logger().
					WithError(err).
					WithField(core.LogFieldProtocolVersion, protocol.Version()).
					Warn("Error while closing client for gRPC stream")
			}
		}
	})
}

func (mc *conn) IsConnected() bool {
	mc.mux.RLock()
	defer mc.mux.RUnlock()

	return len(mc.streams) > 0
}

func (mc *conn) IsAuthenticated() bool {
	return mc.Peer().Authenticated
}

func (mc *conn) closeError() *status.Status {
	return mc.status.Load()
}

// receiverShutdownTimeout bounds the wait in waitForReceivers. The receive loops return as soon as the underlying
// streams are closed, unless a message handler does not return, which should not happen but must not block the
// disconnect either.
const receiverShutdownTimeout = 5 * time.Second

func (mc *conn) waitForReceivers() {
	peer := mc.Peer() // copy Peer, because it is reset by disconnect()
	done := make(chan struct{})
	go func() {
		mc.receivers.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(receiverShutdownTimeout):
		log.Logger().
			WithFields(peer.ToFields()).
			Warn("Timeout waiting for the receive loops to exit, the peer's close status may be incomplete")
	}
}
