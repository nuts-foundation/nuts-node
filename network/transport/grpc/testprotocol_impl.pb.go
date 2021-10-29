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

func (s *TestProtocol) OpenStream(outgoingContext context.Context, grpcConn *grpc.ClientConn, callback func(stream grpc.ClientStream) (transport.Peer, error), closer <-chan struct{}) (context.Context, error) {
	client := NewTestClient(grpcConn)
	clientStream, err := client.DoStuff(outgoingContext)
	if err != nil {
		return nil, err
	}
	peer, err := callback(clientStream)
	s.peer = peer
	if err != nil {
		_ = clientStream.CloseSend()
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
