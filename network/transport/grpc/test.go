package grpc

import (
	"context"
	"crypto/tls"
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

type StubConnectionList struct {
	PeerID transport.PeerID
	Conn   *StubConnection
}

func (s *StubConnectionList) Get(peer transport.PeerID) Connection {
	if peer == s.PeerID {
		if s.Conn == nil {
			s.Conn = &StubConnection{}
		}
		return s.Conn
	}
	return nil
}

func (s StubConnectionList) All() []Connection {
	if s.Conn == nil {
		return nil
	}
	return []Connection{s.Conn}
}

type StubConnection struct {
	SentMsgs []interface{}
}

func (s *StubConnection) Send(_ Protocol, envelope interface{}) error {
	s.SentMsgs = append(s.SentMsgs, envelope)
	return nil
}

func (s StubConnection) Peer() transport.Peer {
	panic("implement me")
}

func (s StubConnection) Connected() bool {
	panic("implement me")
}

func (s StubConnection) disconnect() {
	panic("implement me")
}

func (s StubConnection) waitUntilDisconnected() {
	panic("implement me")
}

func (s StubConnection) startConnecting(_ *tls.Config, _ func(_ *grpc.ClientConn) bool) {
	panic("implement me")
}

func (s StubConnection) stopConnecting() {
	panic("implement me")
}

func (s StubConnection) registerStream(_ Protocol, _ Stream) bool {
	panic("implement me")
}

func (s StubConnection) verifyOrSetPeerID(_ transport.PeerID) bool {
	panic("implement me")
}

func (s StubConnection) stats() transport.ConnectionStats {
	panic("implement me")
}
