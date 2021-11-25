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
	"fmt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"strings"
	"time"
)

// SendMessages is a helper function that sends messages using the given StreamSender.
// It sends a message when the returned callback is invoked. Sending is asynchronous: it uses a channel to avoid blocking the caller while sending the message.
// If the channel is full, the message is dropped and an error is returned.
// The goroutine that reads from the channel and sends the messages is stopped when the given context is cancelled.
func SendMessages(ctx context.Context, peer transport.Peer, sender StreamSender) func(msg interface{}) error {
	done := ctx.Done()

	channel := make(chan interface{}, 20)
	go func() {
		for {
			select {
			case _ = <-done:
				return
			case msg := <-channel:
				err := sender.SendMsg(msg)
				if err != nil {
					log.Logger().Warnf("Unable to send message %T, message is dropped (peer=%s): %v", msg, peer, err)
				}
			}
		}
	}()

	return func(msg interface{}) error {
		if len(channel) >= cap(channel) {
			// This node is a slow responder, we'll have to drop this message because our backlog is full.
			return fmt.Errorf("peer's outbound message backlog has reached max capacity, message is dropped (peer=%s,backlog-size=%d)", peer, cap(channel))
		}
		channel <- msg
		return nil
	}
}

// ReceiveMessages is a helper function which receives messages from the given StreamReceiver.
// The supplied callbacks are invoked when a message is received or an error occurs. The function blocks until an error occurs.
func ReceiveMessages(receiver StreamReceiver, messageCreator func() interface{}, onMessage func(msg interface{})) error {
	for {
		msg := messageCreator()
		err := receiver.RecvMsg(msg)
		if err != nil {
			return err
		}
		onMessage(msg)
	}
}

func readMetadata(md metadata.MD) (transport.PeerID, did.DID, error) {
	val := func(key string, required bool) (string, error) {
		values := md.Get(key)
		if len(values) == 0 {
			if !required {
				return "", nil
			}
			return "", fmt.Errorf("peer didn't send %s header", key)
		} else if len(values) > 1 {
			return "", fmt.Errorf("peer sent multiple values for %s header", key)
		}
		return strings.TrimSpace(values[0]), nil
	}

	// Parse Peer ID
	peerIDStr, err := val(peerIDHeader, true)
	if err != nil {
		return "", did.DID{}, err
	}
	if peerIDStr == "" {
		return "", did.DID{}, fmt.Errorf("peer sent empty %s header", peerIDHeader)
	}
	// Parse Node DID
	nodeDIDStr, err := val(nodeDIDHeader, false)
	if err != nil {
		return "", did.DID{}, err
	}
	var nodeDID did.DID
	if nodeDIDStr != "" {
		parsedNodeDID, err := did.ParseDID(nodeDIDStr)
		if err != nil {
			return "", did.DID{}, fmt.Errorf("peer sent invalid node DID: %w", err)
		}
		nodeDID = *parsedNodeDID
	}
	return transport.PeerID(peerIDStr), nodeDID, nil
}

// GetStreamMethod formats the method name for the given stream.
func GetStreamMethod(serviceName string, stream grpc.StreamDesc) string {
	return fmt.Sprintf("/%s/%s", serviceName, stream.StreamName)
}

func sleepWithCancel(ctx context.Context, duration time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(duration):
	}
}
