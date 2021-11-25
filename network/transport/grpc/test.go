package grpc

import (
	"context"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
	"net"
)

type StubStreamReceiver struct {
	ExpectedError   error
	ExpectedMessage proto.Message
}

func (s *StubStreamReceiver) RecvMsg(m interface{}) error {
	if s.ExpectedMessage != nil {
		bytes, err := proto.Marshal(s.ExpectedMessage)
		if err != nil {
			return err
		}
		err = proto.Unmarshal(bytes, m.(proto.Message))
		if err != nil {
			return err
		}
		s.ExpectedMessage = nil
		return nil
	}
	if s.ExpectedError != nil {
		return s.ExpectedError
	}
	return &closedErr{}
}

type closedErr struct{}

func (g closedErr) Error() string {
	return ""
}

func (g closedErr) GRPCStatus() *status.Status {
	return status.New(codes.Canceled, "connection closed")
}

// NewBufconnConfig creates a new Config like NewConfig, but configures an in-memory bufconn listener instead of a TCP listener.
func NewBufconnConfig(peerID transport.PeerID, options ...ConfigOption) (Config, *bufconn.Listener) {
	bufnet := bufconn.Listen(1024 * 1024)
	return NewConfig("bufnet", peerID, append(options[:], func(config *Config) {
		config.listener = func(_ string) (net.Listener, error) {
			return bufnet, nil
		}
	})...), bufnet
}

// WithBufconnDialer can be used to redirect outbound connections to a predetermined bufconn listener.
func WithBufconnDialer(listener *bufconn.Listener) ConfigOption {
	return func(config *Config) {
		config.dialer = func(ctx context.Context, target string, opts ...grpc.DialOption) (conn *grpc.ClientConn, err error) {
			return grpc.DialContext(ctx, "bufnet", grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
				return listener.Dial()
			}), grpc.WithInsecure())
		}
	}
}

type TestNodeDIDResolver struct {
	nodeDID did.DID
}

func (s TestNodeDIDResolver) Resolve() (did.DID, error) {
	return s.nodeDID, nil
}
