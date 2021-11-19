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
	"context"
	"github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/nuts-foundation/nuts-node/network/transport/v1/protobuf"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const outMessagesBacklog = 1000 // TODO: Does this number make sense? Should also be configurable?

type grpcMessenger interface {
	Send(message *protobuf.NetworkMessage) error
	Recv() (*protobuf.NetworkMessage, error)
}

func exchange(peer transport.Peer, messageReceiver messageQueue, out <-chan *protobuf.NetworkMessage, messenger grpcMessenger, closer <-chan struct{}, cancelFunc context.CancelFunc) {
	// Use copies of pointers to prevent nil deref when close() is called
	in := receiveMessages(peer.ID, messenger)
	for {
		select {
		case message := <-out:
			if message == nil {
				// Connection is closing
				cancelFunc()
				return
			}
			if messenger.Send(message) != nil {
				log.Logger().Warnf("Unable to send message to peer (peer=%s)", peer)
			}
		case message := <-in:
			if message == nil {
				// Connection is closing
				cancelFunc()
				return
			}
			if len(messageReceiver.c) >= cap(messageReceiver.c) {
				// We need to find out if, and when happens. This can probably be triggered by sending lots of messages.
				// It probably doesn't cause issues for the health of the local node, but it might hurt the connection to the particular peer.
				// We might need measures to solve it, like disconnecting or just ignoring the message, for example.
				log.Logger().Warnf("Inbound message backlog for peer has reached its max capacity, message is dropped (peer=%s,backlog-size=%d).", peer, cap(messageReceiver.c))
				continue
			}
			messageReceiver.c <- *message
		case <-closer:
			cancelFunc()
			log.Logger().Trace("closer was invoked, exiting message read/send loop")
			return
		}
	}
}

// receiveMessages spawns a goroutine that receives messages and puts them on the returned channel. The goroutine
// can only be stopped by closing the underlying gRPC connection.
func receiveMessages(peerID transport.PeerID, messenger grpcMessenger) chan *PeerMessage {
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
