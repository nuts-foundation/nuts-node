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
	acceptorCallback StreamAcceptor
	peer             transport.Peer
	inboundCalled    bool
	outboundCalled   bool
}

func (s *TestProtocol) DoStuff(serverStream Test_DoStuffServer) error {
	peer, _, err := s.acceptorCallback(serverStream)
	if err != nil {
		return err
	}
	_, _ = serverStream.Recv()
	s.inboundCalled = true
	s.peer = peer
	return nil
}

func (s *TestProtocol) RegisterService(registrar grpc.ServiceRegistrar, acceptorCallback StreamAcceptor) {
	s.acceptorCallback = acceptorCallback
	RegisterTestServer(registrar, s)
}

func (s *TestProtocol) OpenStream(outgoingContext context.Context, grpcConn *grpc.ClientConn, callback func(stream grpc.ClientStream, method string) (transport.Peer, error), closer <-chan struct{}) (context.Context, error) {
	client := NewTestClient(grpcConn)
	clientStream, err := client.DoStuff(outgoingContext, grpc.FailFastCallOption{FailFast: true})
	if err != nil {
		return nil, err
	}
	peer, err := callback(clientStream, "testprotocol")
	s.peer = peer
	if err != nil {
		_ = clientStream.CloseSend()
		return nil, err
	}
	<-closer
	return context.Background(), nil
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
