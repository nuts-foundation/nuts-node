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

package v2

import (
	"context"
	"fmt"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/nuts-foundation/nuts-node/network/transport/grpc"
	grpcLib "google.golang.org/grpc"
)

var _ grpc.Protocol = (*protocol)(nil)

// New creates an instance of the v2 protocol.
func New(graph dag.DAG, payloadStore dag.PayloadStore) grpc.Protocol {
	return &protocol{
		graph:        graph,
		payloadStore: payloadStore,
	}
}

type protocol struct {
	connectionList    grpc.ConnectionList
	connectionManager transport.ConnectionManager

	payloadStore dag.PayloadStore
	graph        dag.DAG
}

func (p protocol) CreateClientStream(outgoingContext context.Context, grpcConn *grpcLib.ClientConn) (grpcLib.ClientStream, error) {
	return NewProtocolClient(grpcConn).Stream(outgoingContext)
}

func (p *protocol) Register(registrar grpcLib.ServiceRegistrar, acceptor func(stream grpcLib.ServerStream) error, connectionList grpc.ConnectionList, connectionManager transport.ConnectionManager) {
	RegisterProtocolServer(registrar, &protocolServer{acceptor: acceptor})
	p.connectionList = connectionList
	p.connectionManager = connectionManager
}

func (p protocol) MethodName() string {
	return grpc.GetStreamMethod(Protocol_ServiceDesc.ServiceName, Protocol_ServiceDesc.Streams[0])
}

func (p protocol) CreateEnvelope() interface{} {
	return &Envelope{}
}

func (p protocol) UnwrapMessage(envelope interface{}) interface{} {
	return envelope.(*Envelope).Message
}

func (p protocol) Configure(_ transport.PeerID) {
}

func (p protocol) Start() {
}

func (p protocol) Stop() {
}

func (p protocol) Diagnostics() []core.DiagnosticResult {
	return nil
}

func (p protocol) PeerDiagnostics() map[transport.PeerID]transport.Diagnostics {
	return make(map[transport.PeerID]transport.Diagnostics, 0)
}

func (p *protocol) send(peer transport.Peer, message isEnvelope_Message) error {
	connection := p.connectionList.Get(peer.ID)
	if connection == nil {
		return fmt.Errorf("unable to send message, connection not found (peer=%s)", peer)
	}
	return connection.Send(p, &Envelope{Message: message})
}

type protocolServer struct {
	acceptor func(grpcLib.ServerStream) error
}

func (p protocolServer) Stream(server Protocol_StreamServer) error {
	return p.acceptor(server)
}
