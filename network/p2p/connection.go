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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"sync"

	log "github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"google.golang.org/grpc"
)

type grpcMessenger interface {
	Send(message *transport.NetworkMessage) error
	Recv() (*transport.NetworkMessage, error)
}

// connection represents a bidirectional connection with a peer.
type connection struct {
	Peer
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

func (conn *connection) close() {
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
}

func (conn *connection) send(message *transport.NetworkMessage) error {
	conn.mux.Lock()
	defer conn.mux.Unlock()
	if conn.outMessages == nil {
		return errors.New("can't send on closed connection")
	}
	conn.outMessages <- message
	return nil
}

// receiveMessages (blocking) reads messages from the peer until it disconnects or the network is stopped.
func (conn *connection) receiveMessages() chan *PeerMessage {
	peerID := conn.ID
	messenger := conn.messenger
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
				conn.close()
				break
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

func (conn *connection) sendAndReceive(receivedMessages messageQueue) {
	conn.mux.Lock()
	out := conn.outMessages
	in := conn.receiveMessages()
	conn.mux.Unlock()
	for {
		select {
		case message := <-out:
			if message == nil {
				// Connection is closing
				return
			}
			if conn.messenger.Send(message) != nil {
				log.Logger().Warnf("Unable to send message to peer (peer=%s)", conn.Peer)
			}
		case message := <-in:
			if message == nil {
				// Connection is closing
				return
			}
			receivedMessages.c <- *message
		case <-conn.closer:
			log.Logger().Trace("close() is called")
			return
		}
	}
}
