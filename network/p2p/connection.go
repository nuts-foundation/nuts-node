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
	"io"
	"sync"

	log "github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"google.golang.org/grpc"
)

type senderReceiver interface {
	Send(message *transport.NetworkMessage) error
	Recv() (*transport.NetworkMessage, error)
}

func createConnection(peer Peer, messenger senderReceiver) *connection {
	return &connection{
		Peer:        peer,
		messenger:   messenger,
		outMessages: make(chan *transport.NetworkMessage, 10),
		mux:         &sync.Mutex{},
	}
}

// connection represents a bidirectional connection with a peer.
type connection struct {
	Peer
	// messenger is used to send and receive messages
	messenger senderReceiver
	// grpcConn is only filled for peers where we're the connecting party
	grpcConn *grpc.ClientConn
	// outMessages contains the messages we want to send to the peer.
	//   According to the docs it's unsafe to simultaneously call stream.Send() from multiple goroutines so we put them
	//   on a channel so that each peer can have its own goroutine sending messages (consuming messages from this channel)
	outMessages chan *transport.NetworkMessage
	// mux is used to secure access to the internals of this struct since they're accessed concurrently
	mux *sync.Mutex
}

func (conn *connection) close() {
	conn.mux.Lock()
	defer conn.mux.Unlock()
	if conn.grpcConn != nil {
		if err := conn.grpcConn.Close(); err != nil {
			log.Logger().Warnf("Unable to close client connection (peer=%s): %v", conn.Peer, err)
		}
		conn.grpcConn = nil
	}
	if conn.outMessages != nil {
		close(conn.outMessages)
		conn.outMessages = nil
	}
}

func (conn *connection) send(message *transport.NetworkMessage) {
	conn.mux.Lock()
	defer conn.mux.Unlock()
	conn.outMessages <- message
}

// sendMessages (blocking) reads messages from its outMessages channel and sends them to the peer until the channel is closed.
func (conn connection) sendMessages() {
	for message := range conn.outMessages {
		if conn.messenger.Send(message) != nil {
			log.Logger().Warnf("Unable to send message to peer (peer=%s)", conn.Peer)
		}
	}
}

// receiveMessages (blocking) reads messages from the peer until it disconnects or the network is stopped.
func (conn *connection) receiveMessages(receivedMsgQueue messageQueue) {
	for {
		msg, recvErr := conn.messenger.Recv()
		if recvErr != nil {
			if recvErr == io.EOF {
				log.Logger().Infof("Peer closed connection (peer-id=%s)", conn.ID)
			} else {
				log.Logger().Warnf("Peer connection error (peer-id=%s): %v", conn.ID, recvErr)
			}
			break
		}
		log.Logger().Tracef("Received message from peer (peer-id=%s): %s", conn.ID, msg.String())
		receivedMsgQueue.c <- PeerMessage{
			Peer:    conn.ID,
			Message: msg,
		}
	}
	conn.close()
}
