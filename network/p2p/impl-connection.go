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

type messageGate interface {
	Send(message *transport.NetworkMessage) error
	Recv() (*transport.NetworkMessage, error)
}

// connection represents a bidirectional connection with a peer.
type connection struct {
	Peer
	// gate is used to send and receive messages
	gate messageGate
	// grpcConn and client are only filled for peers where we're the connecting party
	grpcConn *grpc.ClientConn
	client   transport.NetworkClient
	// outMessages contains the messages we want to send to the peer.
	//   According to the docs it's unsafe to simultaneously call stream.Send() from multiple goroutines so we put them
	//   on a channel so that each peer can have its own goroutine sending messages (consuming messages from this channel)
	outMessages chan *transport.NetworkMessage
	// closeMutex the close() function since race conditions can trigger panics
	closeMutex *sync.Mutex
}

func (conn *connection) close() {
	conn.closeMutex.Lock()
	defer conn.closeMutex.Unlock()
	if conn.grpcConn != nil {
		if err := conn.grpcConn.Close(); err != nil {
			log.Logger().Errorf("Unable to close client connection (peer=%s): %v", conn.Peer, err)
		}
		conn.grpcConn = nil
	}
	if conn.outMessages != nil {
		close(conn.outMessages)
		conn.outMessages = nil
	}
}

func (conn *connection) send(message *transport.NetworkMessage) {
	conn.closeMutex.Lock()
	defer conn.closeMutex.Unlock()
	conn.outMessages <- message
}

// sendMessages (blocking) reads messages from its outMessages channel and sends them to the peer until the channel is closed.
func (conn connection) sendMessages() {
	for message := range conn.outMessages {
		if conn.gate.Send(message) != nil {
			log.Logger().Errorf("Unable to broadcast message to peer (peer=%s)", conn.Peer)
		}
	}
}

// receiveMessages (blocking) reads messages from the peer until it disconnects or the network is stopped.
func receiveMessages(gate messageGate, peerId PeerID, receivedMsgQueue messageQueue) {
	for {
		msg, recvErr := gate.Recv()
		if recvErr != nil {
			if recvErr == io.EOF {
				log.Logger().Infof("Peer closed connection: %s", peerId)
			} else {
				log.Logger().Errorf("Peer connection error (peer=%s): %v", peerId, recvErr)
			}
			break
		}
		log.Logger().Tracef("Received message from peer (%s): %s", peerId, msg.String())
		receivedMsgQueue.c <- PeerMessage{
			Peer:    peerId,
			Message: msg,
		}
	}
}
