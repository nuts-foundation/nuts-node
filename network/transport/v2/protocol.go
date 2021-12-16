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
	"errors"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/nuts-foundation/nuts-node/network/transport/grpc"
	grpcLib "google.golang.org/grpc"
)

var _ grpc.Protocol = (*protocol)(nil)

// New creates an instance of the v2 protocol.
func New() transport.Protocol {
	return &protocol{}
}

type protocol struct {
	connectionList grpc.ConnectionList
}

func (p protocol) CreateClientStream(outgoingContext context.Context, grpcConn *grpcLib.ClientConn) (grpcLib.ClientStream, error) {
	return NewProtocolClient(grpcConn).Stream(outgoingContext)
}

func (p *protocol) Register(registrar grpcLib.ServiceRegistrar, acceptor func(stream grpcLib.ServerStream) error, connectionList grpc.ConnectionList) {
	RegisterProtocolServer(registrar, &protocolServer{acceptor: acceptor})
	p.connectionList = connectionList
}

func (p protocol) MethodName() string {
	return grpc.GetStreamMethod(Protocol_ServiceDesc.ServiceName, Protocol_ServiceDesc.Streams[0])
}

func (p protocol) CreateEnvelope() interface{} {
	return &Message{}
}

func (p protocol) UnwrapMessage(envelope interface{}) interface{} {
	return envelope.(*Message).Message
}

func (p protocol) Handle(peer transport.Peer, raw interface{}) error {
	envelope := raw.(*Message)
	switch envelope.Message.(type) {
	case *Message_Hello:
		log.Logger().Infof("%T: %s said hello", p, peer)
	default:
		return errors.New("envelope doesn't contain any (handleable) messages")
	}
	return nil
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

type protocolServer struct {
	acceptor func(grpcLib.ServerStream) error
}

func (p protocolServer) Stream(server Protocol_StreamServer) error {
	return p.acceptor(server)
}
