package v2

import (
	"context"
	"errors"
	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/nuts-foundation/nuts-node/network/transport/grpc"
	"github.com/nuts-foundation/nuts-node/test"
	"github.com/stretchr/testify/assert"
	grpcLib "google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func Test_protocol_Stream(t *testing.T) {
	t.Run("ok, send hello, disconnect", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		graph := dag.NewMockDAG(ctrl)
		payloadStore := dag.NewMockPayloadStore(ctrl)
		p := New(graph, payloadStore).(*protocol)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		p.acceptor = func(_ grpcLib.ServerStream) (transport.Peer, context.Context, error) {
			return peer, ctx, nil
		}
		stream := NewMockProtocol_StreamServer(ctrl)
		stream.EXPECT().RecvMsg(gomock.Any()).AnyTimes().DoAndReturn(func(_ interface{}) error {
			<-ctx.Done()
			return io.EOF
		})
		stream.EXPECT().Send(gomock.Any()) // Hello

		err := p.Stream(stream)

		assert.NoError(t, err)
	})
	t.Run("not ok, disconnect", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		graph := dag.NewMockDAG(ctrl)
		payloadStore := dag.NewMockPayloadStore(ctrl)
		p := New(graph, payloadStore).(*protocol)

		p.acceptor = func(_ grpcLib.ServerStream) (transport.Peer, context.Context, error) {
			return peer, nil, errors.New("please disconnect")
		}
		stream := NewMockProtocol_StreamServer(ctrl)

		err := p.Stream(stream)

		assert.EqualError(t, err, "please disconnect")
	})
}

func Test_protocol_replyFunc(t *testing.T) {
	t.Run("wraps message in an envelope", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		streamSender := grpc.NewMockStreamSender(ctrl)
		wg := sync.WaitGroup{}
		wg.Add(1)
		streamSender.EXPECT().SendMsg(&Envelope{Message: &Envelope_Hello{Hello: &Hello{}}}).DoAndReturn(func(_ interface{}) error {
			wg.Done()
			return nil
		})
		err := replyFunc(context.Background(), transport.Peer{}, streamSender)(&Envelope_Hello{Hello: &Hello{}})
		assert.NoError(t, err)

		// Wait until sender has been called
		wg.Wait()
	})
}

func Test_protocol_receiveMessages(t *testing.T) {
	t.Run("receives message", func(t *testing.T) {
		peer := transport.Peer{
			ID:      "abc",
			Address: "abc:5555",
		}

		ctrl := gomock.NewController(t)
		graph := dag.NewMockDAG(ctrl)
		payloadStore := dag.NewMockPayloadStore(ctrl)
		p := New(graph, payloadStore).(*protocol)
		receiver := grpc.StubStreamReceiver{ExpectedMessage: &Envelope{Message: &Envelope_Hello{Hello: &Hello{}}}}

		p.receiveMessages(peer, &receiver, nil)

		test.WaitFor(t, func() (bool, error) {
			return receiver.ExpectedMessage == nil, nil
		}, time.Second, "time-out while waiting for message to be consumed")
	})
}

func Test_protocol_Start(t *testing.T) {
	// Doesn't do anything yet
	protocol{}.Start()
}

func Test_protocol_Configure(t *testing.T) {
	// Doesn't do anything yet
	protocol{}.Configure("")
}

func Test_protocol_Stop(t *testing.T) {
	// Doesn't do anything yet
	protocol{}.Stop()
}

func Test_protocol_Diagnostics(t *testing.T) {
	// Doesn't do anything yet
	assert.Empty(t, protocol{}.Diagnostics())
}

func Test_protocol_PeerDiagnostics(t *testing.T) {
	// Doesn't do anything yet
	assert.Empty(t, protocol{}.PeerDiagnostics())
}

func Test_protocol_OpenStream(t *testing.T) {
	// Setup: create protocol
	ctrl := gomock.NewController(t)
	graph := dag.NewMockDAG(ctrl)
	payloadStore := dag.NewMockPayloadStore(ctrl)
	p := New(graph, payloadStore).(*protocol)

	// Setup: Start gRPC transport
	cfg, listener := grpc.NewBufconnConfig("test")
	connectionManager := grpc.NewGRPCConnectionManager(cfg, grpc.TestNodeDIDResolver{}, nil, p)
	err := connectionManager.Start()
	if !assert.NoError(t, err) {
		return
	}
	defer connectionManager.Stop()

	// Setup: Create gRPC connection
	dial := func() *grpcLib.ClientConn {
		clientConn, err := grpcLib.DialContext(context.Background(), "bufnet", grpcLib.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return listener.Dial()
		}), grpcLib.WithInsecure())
		if !assert.NoError(t, err) {
			return nil
		}
		return clientConn
	}

	t.Run("ok", func(t *testing.T) {
		// Perform: Use gRPC connection to open stream
		clientConn := dial()
		defer clientConn.Close()
		outgoingCtx := metadata.NewOutgoingContext(context.Background(), metadata.New(map[string]string{"peerID": "foo"}))
		ctx, err := p.OpenStream(outgoingCtx, clientConn, func(s grpcLib.ClientStream, method string) (transport.Peer, error) {
			return transport.Peer{}, nil
		})
		if !assert.NoError(t, err) {
			return
		}

		// Assert: wait for connection to be registered
		test.WaitFor(t, func() (bool, error) {
			return len(connectionManager.Peers()) == 1, nil
		}, 5*time.Second, "time-out while waiting for connection")

		// Teardown
		clientConn.Close()
		<-ctx.Done()
	})
	t.Run("error - peer connection is rejected by connection manager", func(t *testing.T) {
		expectedError := errors.New("I don't like this peer")
		// Perform: Use gRPC connection to open stream, but connection manager refuses the connection
		clientConn := dial()
		defer clientConn.Close()

		outgoingCtx := metadata.NewOutgoingContext(context.Background(), metadata.New(map[string]string{"peerID": "foo"}))
		ctx, err := p.OpenStream(metadata.NewOutgoingContext(outgoingCtx, metadata.New(map[string]string{"peerID": "foo"})), clientConn, func(stream grpcLib.ClientStream, method string) (transport.Peer, error) {
			return transport.Peer{}, expectedError
		})

		// Assert: make sure there are no connected peers
		assert.Equal(t, expectedError, err)
		assert.Empty(t, connectionManager.Peers())

		assert.Nil(t, ctx)
	})
}
