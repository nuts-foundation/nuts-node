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
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"google.golang.org/grpc"
)

type TestProtocol struct {
	peer           transport.Peer
	inboundCalled  bool
	outboundCalled bool
	acceptor       func(stream grpc.ServerStream) error
}

func (s *TestProtocol) MethodName() string {
	return GetStreamMethod(Test_ServiceDesc.ServiceName, Test_ServiceDesc.Streams[0])
}

func (s *TestProtocol) CreateClientStream(outgoingContext context.Context, grpcConn *grpc.ClientConn) (grpc.ClientStream, error) {
	client := NewTestClient(grpcConn)
	return client.DoStuff(outgoingContext, grpc.FailFastCallOption{FailFast: true})
}

func (s *TestProtocol) Register(registrar grpc.ServiceRegistrar, acceptor func(stream grpc.ServerStream) error, connectionList ConnectionList) {
	RegisterTestServer(registrar, s)
	s.acceptor = acceptor
}

func (s *TestProtocol) CreateEnvelope() interface{} {
	return &TestMessage{}
}

func (s *TestProtocol) Handle(peer transport.Peer, envelope interface{}) error {
	panic("implement me")
}

func (s *TestProtocol) UnwrapMessage(envelope interface{}) interface{} {
	panic("implement me")
}

func (s *TestProtocol) DoStuff(serverStream Test_DoStuffServer) error {
	s.inboundCalled = true
	return s.acceptor(serverStream)
}

func (s TestProtocol) Configure(_ transport.PeerID) {
}

func (s TestProtocol) Start() {
}

func (s TestProtocol) Stop() {
}

func (s TestProtocol) Diagnostics() []core.DiagnosticResult {
	return nil
}

func (s TestProtocol) PeerDiagnostics() map[transport.PeerID]transport.Diagnostics {
	return nil
}
