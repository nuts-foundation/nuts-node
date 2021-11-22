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
	"fmt"
	"github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/nuts-foundation/nuts-node/network/transport/grpc"
	"github.com/nuts-foundation/nuts-node/network/transport/v1/protobuf"
	grpcLib "google.golang.org/grpc"
	"sync"
)

const eventChannelSize = 100
const messageBacklogChannelSize = 1000 // TODO: Does this number make sense? Should also be configurable?
const defaultMaxMessageSizeInBytes = 1024 * 512

// MaxMessageSizeInBytes defines the maximum size of an in- or outbound gRPC/Protobuf message
var MaxMessageSizeInBytes = defaultMaxMessageSizeInBytes

type adapter struct {
	// Event channels which are listened to by, peers connects/disconnects
	peerConnectedChannel    chan transport.Peer
	peerDisconnectedChannel chan transport.Peer

	// peerOutMessages contains the messages we want to send to the peer.
	//   According to the docs it's unsafe to simultaneously call stream.Send() from multiple goroutines so we put them
	//   on a channel so that each peer can have its own goroutine sending messages (consuming messages from this channel)
	peerOutMessages map[transport.PeerID]chan *protobuf.NetworkMessage
	// peerMessengers is used to send and receive messages.
	peerMessengers map[transport.PeerID]grpcMessenger
	// peerMux is used to protect access to peerOutMessages and peerMessengers
	peerMux *sync.Mutex

	receivedMessages messageQueue
	acceptor         grpc.InboundStreamHandler
}

func (n adapter) OpenStream(outgoingContext context.Context, grpcConn *grpcLib.ClientConn, callback func(stream grpcLib.ClientStream, method string) (transport.Peer, error)) (context.Context, error) {
	client := protobuf.NewNetworkClient(grpcConn)
	messenger, err := client.Connect(outgoingContext)
	peer, err := callback(messenger, grpc.GetStreamMethod(protobuf.Network_ServiceDesc.ServiceName, protobuf.Network_ServiceDesc.Streams[0]))
	if err != nil {
		_ = messenger.CloseSend()
		return nil, err
	}
	return n.acceptPeer(outgoingContext, peer, messenger), nil
}

func (n adapter) EventChannels() (peerConnected chan transport.Peer, peerDisconnected chan transport.Peer) {
	return n.peerConnectedChannel, n.peerDisconnectedChannel
}

func (n *adapter) Broadcast(message *protobuf.NetworkMessage) {
	n.peerMux.Lock()
	defer n.peerMux.Unlock()

	for peerID, out := range n.peerOutMessages {
		err := sendTo(peerID, out, message)
		if err != nil {
			log.Logger().Warnf("Unable to broadcast message: %v", err)
		}
	}
}

func (n adapter) ReceivedMessages() MessageQueue {
	return n.receivedMessages
}

func (n *adapter) Send(peerID transport.PeerID, message *protobuf.NetworkMessage) error {
	n.peerMux.Lock()
	defer n.peerMux.Unlock()
	out := n.peerOutMessages[peerID]
	if out == nil {
		return fmt.Errorf("unknown peer: %s", peerID)
	}
	return sendTo(peerID, out, message)
}

func sendTo(peerID transport.PeerID, out chan<- *protobuf.NetworkMessage, message *protobuf.NetworkMessage) error {
	if len(out) >= cap(out) {
		// This node is a slow responder, we'll have to drop this message because our backlog is full.
		return fmt.Errorf("peer's outbound message backlog has reached max capacity, message is dropped (peer=%s,backlog-size=%d)", peerID, cap(out))
	}
	out <- message
	return nil
}

// NewAdapter creates an interface to be used connect to peers in the network and exchange messages.
func NewAdapter() Adapter {
	return &adapter{
		peerConnectedChannel:    make(chan transport.Peer, eventChannelSize),
		peerDisconnectedChannel: make(chan transport.Peer, eventChannelSize),
		receivedMessages:        messageQueue{c: make(chan PeerMessage, messageBacklogChannelSize)},
		peerMux:                 &sync.Mutex{},
		peerOutMessages:         make(map[transport.PeerID]chan *protobuf.NetworkMessage),
		peerMessengers:          make(map[transport.PeerID]grpcMessenger),
	}
}

type messageQueue struct {
	c chan PeerMessage
}

func (m messageQueue) Get() PeerMessage {
	return <-m.c
}

func (n *adapter) RegisterService(registrar grpcLib.ServiceRegistrar, acceptor grpc.InboundStreamHandler) {
	n.acceptor = acceptor
	protobuf.RegisterNetworkServer(registrar, n)
}

// Connect is the callback that is called from the GRPC layer when a new client connects
func (n adapter) Connect(stream protobuf.Network_ConnectServer) error {
	peer, closer, err := n.acceptor(stream)
	if err != nil {
		log.Logger().Warnf("ProtocolV1: Inbound stream not accepted, returning error to client: %v", err)
		return err
	}
	ctx := n.acceptPeer(closer, peer, stream)
	<-ctx.Done()
	return nil
}

// acceptPeer registers a connection, associating the gRPC stream with the given peer.
// It starts the goroutines required for receiving and sending messages from/to the peer.
// It should be called from the gRPC service handler (inbound) and for outbound gRPC service calls.
// This function does not block: the spawned goroutines exit when it reads an item from the closer channel.
// When the service call is aborted (either by the local node or the remote peer) it cancels the returned context.
func (n *adapter) acceptPeer(ctx context.Context, peer transport.Peer, messenger grpcMessenger) context.Context {
	out := make(chan *protobuf.NetworkMessage, outMessagesBacklog)
	n.peerMux.Lock()
	n.peerOutMessages[peer.ID] = out
	n.peerMessengers[peer.ID] = messenger
	n.peerMux.Unlock()
	streamContext, cancelFunc := context.WithCancel(context.Background())
	go func() {
		exchange(ctx, peer, n.receivedMessages, out, messenger, cancelFunc)
		n.peerMux.Lock()
		delete(n.peerOutMessages, peer.ID)
		delete(n.peerMessengers, peer.ID)
		n.peerMux.Unlock()
	}()
	return streamContext
}
