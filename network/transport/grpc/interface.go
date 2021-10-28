package grpc

import (
	"github.com/nuts-foundation/nuts-node/network/transport"
	"google.golang.org/grpc"
)

// ServiceImplementor allows Protocol implementations to expose a gRPC service.
type ServiceImplementor interface {
	RegisterService(registrar grpc.ServiceRegistrar, acceptorCallback StreamAcceptor)
}

// StreamAcceptor defines a function for accepting gRPC streams.
// The following values are returned:
// - `accepted` which indicates whether the stream has been accepted or not. If not accepted, the stream must be terminated.
// - `peer` which holds information about the specific peer.
// - `closer` channel which is used to signal when the stream must be closed.
type StreamAcceptor func(serverStream grpc.ServerStream) (accepted bool, peer transport.Peer, closer chan struct{})
