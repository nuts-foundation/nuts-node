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

package p2p

import (
	"errors"
	"fmt"
	"github.com/nuts-foundation/nuts-node/network/protocol/types"
	"github.com/nuts-foundation/nuts-node/network/protocol/v1/transport"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"sync"

	log "github.com/nuts-foundation/nuts-node/network/log"
	"google.golang.org/grpc"
)

const outMessagesBacklog = 1000 // TODO: Does this number make sense? Should also be configurable?

type grpcMessenger interface {
	Send(message *transport.NetworkMessage) error
	Recv() (*transport.NetworkMessage, error)
}

type connection interface {
	// exchange must be called on the connection for it to start sending (using send()) and receiving messages.
	// Received messages are passed to the messageReceiver message queue. It blocks until the connection is closed,
	// by either the peer or the local node.
	exchange(messageReceiver messageQueue)
	// send sends the given message to the peer. It should not be called if exchange() isn't called yet.
	send(message *transport.NetworkMessage) error
	// peer returns information about the peer associated with this connection.
	peer() types.Peer
}

func newConnection(peer types.Peer, messenger grpcMessenger) *managedConnection {
	return &managedConnection{
		Peer:        peer,
		messenger:   messenger,
		outMessages: make(chan *transport.NetworkMessage, outMessagesBacklog),
		closer:      make(chan struct{}, 1),
		mux:         &sync.Mutex{},
	}
}

// managedConnection represents a bidirectional connection with a peer, managed by connectionManager.
type managedConnection struct {
	types.Peer
	// messenger is used to send and receive messages
	messenger grpcMessenger
	// grpcConn is only filled for peers where we're the connecting party
	grpcConn *grpc.ClientConn
	// outMessages contains the messages we want to send to the peer.
	//   According to the docs it's unsafe to simultaneously call stream.Send() from multiple goroutines so we put them
	//   on a channel so that each peer can have its own goroutine sending messages (consuming messages from this channel)
	outMessages chan *transport.NetworkMessage
	closer      chan struct{}
	// mux is used to secure access to the internals of this struct since they're accessed concurrently
	mux *sync.Mutex
}

func (conn *managedConnection) peer() types.Peer {
	conn.mux.Lock()
	defer conn.mux.Unlock()
	return conn.Peer
}

func (conn *managedConnection) send(message *transport.NetworkMessage) error {
	conn.mux.Lock()
	defer conn.mux.Unlock()
	if conn.outMessages == nil {
		return errors.New("can't send on closed connection")
	}
	if len(conn.outMessages) >= cap(conn.outMessages) {
		// This node is a slow responder, we'll have to drop this message because our backlog is full.
		return fmt.Errorf("peer's outbound message backlog has reached max capacity, message is dropped (peer=%s,backlog-size=%d)", conn.Peer, cap(conn.outMessages))
	}
	conn.outMessages <- message
	return nil
}

func (conn *managedConnection) exchange(messageReceiver messageQueue) {
	conn.mux.Lock()
	if conn.messenger == nil {
		log.Logger().Tracef("Connection already closed (peer=%s)", conn.Peer)
		conn.mux.Unlock()
		return
	}
	// Use copies of pointers to prevent nil deref when close() is called
	out := conn.outMessages
	in := receiveMessages(conn.ID, conn.messenger)
	messenger := conn.messenger
	conn.mux.Unlock()
	for {
		select {
		case message := <-out:
			if message == nil {
				// Connection is closing
				return
			}
			if messenger.Send(message) != nil {
				log.Logger().Warnf("Unable to send message to peer (peer=%s)", conn.Peer)
			}
		case message := <-in:
			if message == nil {
				// Connection is closing
				return
			}
			if len(messageReceiver.c) >= cap(messageReceiver.c) {
				// We need to find out if, and when happens. This can probably be triggered by sending lots of messages.
				// It probably doesn't cause issues for the health of the local node, but it might hurt the connection to the particular peer.
				// We might need measures to solve it, like disconnecting or just ignoring the message, for example.
				log.Logger().Warnf("Inbound message backlog for peer has reached its max capacity, message is dropped (peer=%s,backlog-size=%d).", conn.Peer, cap(messageReceiver.c))
				continue
			}
			messageReceiver.c <- *message
		case <-conn.closer:
			log.Logger().Trace("close() is called")
			return
		}
	}
}

func (conn *managedConnection) close() {
	conn.mux.Lock()
	defer conn.mux.Unlock()
	if conn.outMessages == nil {
		// Already closed
		return
	}
	log.Logger().Debugf("Connection is closing (peer-id=%s)", conn.ID)

	// Signal send/receive loop connection is closing
	if len(conn.closer) == 0 {
		conn.closer <- struct{}{}
	}
	// Close our client connection (not applicable if we're the server side of the connection)
	if conn.grpcConn != nil {
		if err := conn.grpcConn.Close(); err != nil {
			log.Logger().Warnf("Unable to close client connection (peer=%s): %v", conn.Peer, err)
		}
		conn.grpcConn = nil
	}
	// Close in/out channels
	close(conn.outMessages)
	conn.outMessages = nil

	conn.messenger = nil
}

// receiveMessages spawns a goroutine that receives messages and puts them on the returned channel. The goroutine
// can only be stopped by closing the underlying gRPC connection.
func receiveMessages(peerID types.PeerID, messenger grpcMessenger) chan *PeerMessage {
	result := make(chan *PeerMessage, 10)
	go func() {
		for {
			msg, recvErr := messenger.Recv()
			if recvErr != nil {
				errStatus, isStatusError := status.FromError(recvErr)
				if isStatusError && errStatus.Code() == codes.Canceled {
					log.Logger().Infof("Peer closed connection (peer-id=%s)", peerID)
				} else {
					log.Logger().Warnf("Peer connection error (peer-id=%s): %v", peerID, recvErr)
				}
				close(result)
				return
			}
			log.Logger().Tracef("Received message from peer (peer-id=%s): %s", peerID, msg.String())
			result <- &PeerMessage{
				Peer:    peerID,
				Message: msg,
			}
		}
	}()
	return result
}

func newConnectionManager() *connectionManager {
	return &connectionManager{
		mux:         &sync.RWMutex{},
		conns:       make(map[types.PeerID]*managedConnection, 0),
		peersByAddr: make(map[string]types.PeerID, 0),
	}
}

type connectionManager struct {
	mux         *sync.RWMutex
	conns       map[types.PeerID]*managedConnection
	peersByAddr map[string]types.PeerID
}

// register adds a new connection associated with peer. It uses the given messenger to send/receive messages.
// If a connection with peer already exists, it is closed (and the new one is accepted).
func (mgr *connectionManager) register(peer types.Peer, messenger grpcMessenger) connection {
	if mgr.close(peer.ID) {
		log.Logger().Warnf("Already connected to peer, closed old connection (peer=%s)", peer)
	}

	conn := newConnection(peer, messenger)

	mgr.mux.Lock()
	defer mgr.mux.Unlock()

	mgr.conns[conn.ID] = conn
	mgr.peersByAddr[normalizeAddress(conn.Address)] = conn.ID
	return conn
}

// isConnected returns true if a peer with addr is connected, otherwise false.
func (mgr *connectionManager) isConnected(addr string) bool {
	mgr.mux.RLock()
	defer mgr.mux.RUnlock()
	_, ok := mgr.peersByAddr[normalizeAddress(addr)]
	return ok
}

// get returns the connection associated with peer, or nil if it isn't connected.
func (mgr *connectionManager) get(peer types.PeerID) connection {
	mgr.mux.RLock()
	defer mgr.mux.RUnlock()
	conn, ok := mgr.conns[peer]
	if ok {
		return conn
	}
	return nil
}

// close closes the connection associated with peer. It returns true if the peer was connected, otherwise false.
func (mgr *connectionManager) close(peer types.PeerID) bool {
	mgr.mux.Lock()
	defer mgr.mux.Unlock()
	conn, ok := mgr.conns[peer]
	if !ok {
		return false
	}
	conn.close()
	delete(mgr.conns, conn.ID)
	delete(mgr.peersByAddr, normalizeAddress(conn.Address))
	return true
}

// stop() closes all connections in the connectionManager and resets the internal state.
func (mgr *connectionManager) stop() {
	mgr.mux.Lock()
	defer mgr.mux.Unlock()
	for _, conn := range mgr.conns {
		conn.close()
	}
	mgr.conns = map[types.PeerID]*managedConnection{}
	mgr.peersByAddr = map[string]types.PeerID{}
}

// forEach applies fn to each connection.
func (mgr *connectionManager) forEach(fn func(conn connection)) {
	mgr.mux.RLock()
	defer mgr.mux.RUnlock()
	for _, conn := range mgr.conns {
		fn(conn)
	}
}
