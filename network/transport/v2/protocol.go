package v2

import (
	"context"
	"fmt"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/nuts-foundation/nuts-node/network/transport/grpc"
	grpcLib "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func New() transport.Protocol {
	return &protocol{}
}

type protocol struct {
	acceptor grpc.InboundStreamHandler
}

func (p protocol) RegisterService(registrar grpcLib.ServiceRegistrar, acceptor grpc.InboundStreamHandler) {
	p.acceptor = acceptor
	RegisterProtocolServer(registrar, p)
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

// OpenStream is called when an outbound stream is opened to a remote peer.
func (p protocol) OpenStream(outgoingContext context.Context, grpcConn *grpcLib.ClientConn, callback func(stream grpcLib.ClientStream, method string) (transport.Peer, error)) (context.Context, error) {
	client := NewProtocolClient(grpcConn)
	stream, err := client.Stream(outgoingContext)
	peer, err := callback(stream, grpc.GetStreamMethod(Protocol_ServiceDesc.ServiceName, Protocol_ServiceDesc.Streams[0]))
	if err != nil {
		_ = stream.CloseSend()
		return nil, err
	}

	err = stream.Send(&Message{Message: &Message_Hello{}})
	if err != nil {
		return nil, fmt.Errorf("unable to say hello: %w", err)
	}

	ctx, cancelFn := context.WithCancel(context.Background())
	go func() {
		p.receiveMessages(peer, stream)
		cancelFn()
	}()

	return ctx, nil
}

// Stream is called when a peer opens a stream to the local node (inbound connections).
func (p protocol) Stream(stream Protocol_StreamServer) error {
	peer, ctx, err := p.acceptor(stream)
	if err != nil {
		log.Logger().Warnf("ProtocolV2: Inbound stream not accepted, returning error to client: %v", err)
		return err
	}

	err = stream.Send(&Message{Message: &Message_Hello{}})
	if err != nil {
		return fmt.Errorf("unable to say hello: %w", err)
	}

	go func() {
		p.receiveMessages(peer, stream)
	}()
	<-ctx.Done()
	return nil
}

func (p protocol) receiveMessages(peer transport.Peer, stream grpc.StreamReceiver) {
	grpc.ReceiveMessages(stream, func() interface{} {
		return &Message{}
	}, func(rawMsg interface{}) {
		p.handle(peer, rawMsg.(*Message))
	}, func(err error) {
		errStatus, isStatusError := status.FromError(err)
		if isStatusError && errStatus.Code() == codes.Canceled {
			log.Logger().Infof("%T: Peer closed connection (peer=%s)", p, peer)
		} else {
			log.Logger().Warnf("%T: Peer connection error (peer=%s): %v", p, peer, err)
		}
	})
}

func (p protocol) handle(peer transport.Peer, message *Message) {
	switch message.Message.(type) {
	case *Message_Hello:
		log.Logger().Infof("%T: %s said hello", p, peer)
	default:
		log.Logger().Warnf("%T: Envelope doesn't contain any (handleable) messages, peer sent an empty message or protocol implementation might differ? (peer=%s)", p, peer)
	}
}
