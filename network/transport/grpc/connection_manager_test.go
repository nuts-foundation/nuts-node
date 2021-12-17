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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crl"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/nuts-foundation/nuts-node/test"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/test/bufconn"
	"hash/crc32"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// newBufconnConfig creates a new Config like NewConfig, but configures an in-memory bufconn listener instead of a TCP listener.
func newBufconnConfig(peerID transport.PeerID, options ...ConfigOption) (Config, *bufconn.Listener) {
	bufnet := bufconn.Listen(1024 * 1024)
	return NewConfig("bufnet", peerID, append(options[:], func(config *Config) {
		config.listener = func(_ string) (net.Listener, error) {
			return bufnet, nil
		}
	})...), bufnet
}

// withBufconnDialer can be used to redirect outbound connections to a predetermined bufconn listener.
func withBufconnDialer(listener *bufconn.Listener) ConfigOption {
	return func(config *Config) {
		config.dialer = func(ctx context.Context, target string, opts ...grpc.DialOption) (conn *grpc.ClientConn, err error) {
			return grpc.DialContext(ctx, "bufnet", grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
				return listener.Dial()
			}), grpc.WithInsecure())
		}
	}
}

func Test_grpcConnectionManager_Connect(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		p := &TestProtocol{}
		cm := NewGRPCConnectionManager(NewConfig("", "test"), &stubNodeDIDReader{}, nil, p).(*grpcConnectionManager)

		peerAddress := fmt.Sprintf("127.0.0.1:%d", test.FreeTCPPort())
		cm.Connect(peerAddress)
		assert.Len(t, cm.connections.list, 1)
	})

	t.Run("duplicate connection", func(t *testing.T) {
		p := &TestProtocol{}
		cm := NewGRPCConnectionManager(NewConfig("", "test"), &stubNodeDIDReader{}, nil, p).(*grpcConnectionManager)

		peerAddress := fmt.Sprintf("127.0.0.1:%d", test.FreeTCPPort())
		cm.Connect(peerAddress)
		cm.Connect(peerAddress)
		assert.Len(t, cm.connections.list, 1)
	})

	t.Run("already connected to the peer (inbound)", func(t *testing.T) {
		serverCfg, serverListener := newBufconnConfig("server")
		server := NewGRPCConnectionManager(serverCfg, &stubNodeDIDReader{}, nil).(*grpcConnectionManager)
		if err := server.Start(); err != nil {
			t.Fatal(err)
		}
		defer server.Stop()

		clientCfg, _ := newBufconnConfig("client", withBufconnDialer(serverListener))
		client := NewGRPCConnectionManager(clientCfg, &stubNodeDIDReader{}, nil, &TestProtocol{}).(*grpcConnectionManager)
		if err := client.Start(); err != nil {
			t.Fatal(err)
		}
		defer server.Stop()
		client.Connect("server")
	})
}

func Test_grpcConnectionManager_Peers(t *testing.T) {
	create := func(t *testing.T, opts ...ConfigOption) (*grpcConnectionManager, *MockAuthenticator, *TestProtocol, *bufconn.Listener) {
		ctrl := gomock.NewController(t)
		authenticator := NewMockAuthenticator(ctrl)
		proto := &TestProtocol{}
		cfg, listener := newBufconnConfig(transport.PeerID(t.Name()), opts...)
		cm := NewGRPCConnectionManager(cfg, &stubNodeDIDReader{}, authenticator, proto).(*grpcConnectionManager)
		if err := cm.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			cm.Stop()
		})
		return cm, authenticator, proto, listener
	}

	t.Run("no peers", func(t *testing.T) {
		cm, _, _, _ := create(t)
		assert.Empty(t, cm.Peers())
	})
	t.Run("1 peer (1 connection)", func(t *testing.T) {
		_, authenticator1, _, listener := create(t)
		authenticator1.EXPECT().Authenticate(*nodeDID, gomock.Any(), gomock.Any()).Return(transport.Peer{}, nil)
		cm2, authenticator2, _, _ := create(t, withBufconnDialer(listener))
		authenticator2.EXPECT().Authenticate(*nodeDID, gomock.Any(), gomock.Any()).Return(transport.Peer{}, nil)
		cm2.Connect("bufnet")
		test.WaitFor(t, func() (bool, error) {
			return len(cm2.Peers()) > 0, nil
		}, time.Second*2, "waiting for peer 1 to connect")
	})
	t.Run("0 peers (1 connection which failed)", func(t *testing.T) {
		cm, _, _, _ := create(t)
		cm.Connect("non-existing")
		assert.Empty(t, cm.Peers())
	})
}

func Test_grpcConnectionManager_Start(t *testing.T) {
	t.Run("ok - gRPC server not bound", func(t *testing.T) {
		cm := NewGRPCConnectionManager(Config{}, &stubNodeDIDReader{}, nil).(*grpcConnectionManager)
		assert.NoError(t, cm.Start())
		assert.Nil(t, cm.listener)
	})

	t.Run("ok - gRPC server bound, TLS enabled", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		trustStore, _ := core.LoadTrustStore("../../test/truststore.pem")
		serverCert, _ := tls.LoadX509KeyPair("../../test/certificate-and-key.pem", "../../test/certificate-and-key.pem")
		cfg := NewConfig(
			fmt.Sprintf("127.0.0.1:%d",
				test.FreeTCPPort()),
			"foo",
			WithTLS(serverCert, trustStore, 10),
		)
		cm := NewGRPCConnectionManager(cfg, &stubNodeDIDReader{}, nil).(*grpcConnectionManager)
		err := cm.Start()
		if !assert.NoError(t, err) {
			return
		}
		defer cm.Stop()

		assert.NotNil(t, cm.listener)
	})

	t.Run("ok - gRPC server bound, TLS disabled", func(t *testing.T) {
		cm := NewGRPCConnectionManager(NewConfig(fmt.Sprintf("127.0.0.1:%d", test.FreeTCPPort()), "foo"), &stubNodeDIDReader{}, nil).(*grpcConnectionManager)
		err := cm.Start()
		if !assert.NoError(t, err) {
			return
		}
		defer cm.Stop()

		assert.NotNil(t, cm.listener)
	})

	t.Run("configures CRL check when TLS is enabled", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		p := &TestProtocol{}

		var tlsConfig *tls.Config

		validator := crl.NewMockValidator(gomock.NewController(t))
		validator.EXPECT().SyncLoop(gomock.Any())
		validator.EXPECT().Configure(gomock.Any(), 10).DoAndReturn(func(config *tls.Config, maxValidityDays int) {
			tlsConfig = config
		})

		cm := NewGRPCConnectionManager(Config{
			listenAddress:      fmt.Sprintf(":%d", test.FreeTCPPort()),
			trustStore:         x509.NewCertPool(),
			crlValidator:       validator,
			maxCRLValidityDays: 10,
			listener:           tcpListenerCreator,
		}, &stubNodeDIDReader{}, nil, p)

		assert.NoError(t, cm.Start())
		cm.Stop()

		assert.Equal(t, core.MinTLSVersion, tlsConfig.MinVersion)
	})
}

func Test_grpcConnectionManager_Stop(t *testing.T) {
	t.Run("closes open connections", func(t *testing.T) {
		cm := NewGRPCConnectionManager(Config{peerID: "12345"}, &stubNodeDIDReader{}, nil).(*grpcConnectionManager)

		go cm.handleInboundStream(&TestProtocol{}, newServerStream("1234", ""))
		test.WaitFor(t, func() (bool, error) {
			return len(cm.Peers()) == 1, nil
		}, 5*time.Second, "time-out while waiting for connection")

		cm.Stop()
		assert.Empty(t, cm.Peers())
	})

}

func Test_grpcConnectionManager_Diagnostics(t *testing.T) {
	const peerID = "server-peer-id"
	t.Run("no peers", func(t *testing.T) {
		cm := NewGRPCConnectionManager(Config{peerID: peerID}, &stubNodeDIDReader{}, nil).(*grpcConnectionManager)
		defer cm.Stop()
		assert.Equal(t, "0", cm.Diagnostics()[1].String()) // assert number_of_peers
	})
	t.Run("with peers", func(t *testing.T) {
		cm := NewGRPCConnectionManager(Config{peerID: peerID}, &stubNodeDIDReader{}, nil).(*grpcConnectionManager)
		defer cm.Stop()

		go cm.handleInboundStream(&TestProtocol{}, newServerStream("peer1", ""))
		go cm.handleInboundStream(&TestProtocol{}, newServerStream("peer2", ""))

		test.WaitFor(t, func() (bool, error) {
			return len(cm.Peers()) == 2, nil
		}, 5*time.Second, "time-out while waiting for peers to connect")

		assert.Equal(t, "2", cm.Diagnostics()[1].String())                                         // assert number_of_peers
		assert.Equal(t, "peer2@127.0.0.1:1028 peer1@127.0.0.1:6718", cm.Diagnostics()[2].String()) // assert peers
	})
}

func Test_grpcConnectionManager_openOutboundStreams(t *testing.T) {
	t.Run("client does not support gRPC protocol implementation", func(t *testing.T) {
		serverCfg, serverListener := newBufconnConfig("server")
		server := NewGRPCConnectionManager(serverCfg, &stubNodeDIDReader{}, nil).(*grpcConnectionManager)
		if err := server.Start(); err != nil {
			t.Fatal(err)
		}
		defer server.Stop()

		clientCfg, _ := newBufconnConfig("client", withBufconnDialer(serverListener))
		client := NewGRPCConnectionManager(clientCfg, &stubNodeDIDReader{}, nil, &TestProtocol{}).(*grpcConnectionManager)

		var capturedError atomic.Value
		var waiter sync.WaitGroup
		waiter.Add(1)

		connection, _ := client.connections.getOrRegister(transport.Peer{Address: "server"}, client.dialer)
		connection.startConnecting(nil, func(grpcConn *grpc.ClientConn) bool {
			err := client.openOutboundStreams(connection, grpcConn)
			capturedError.Store(err)
			waiter.Done()
			connection.stopConnecting()
			connection.disconnect()
			return true
		})

		waiter.Wait()
		assert.EqualError(t, capturedError.Load().(error), "could not use any of the supported protocols to communicate with peer (id=@server)")
	})
}

func Test_grpcConnectionManager_handleInboundStream(t *testing.T) {
	protocol := &TestProtocol{}
	t.Run("new client", func(t *testing.T) {
		expectedPeer := transport.Peer{
			ID:      "client-peer-id",
			Address: "127.0.0.1:9522",
			NodeDID: did.DID{},
		}
		clientDID, _ := did.ParseDID("did:nuts:client")
		expectedPeer.NodeDID = *clientDID
		serverStream := newServerStream(expectedPeer.ID, expectedPeer.NodeDID.String())
		ctrl := gomock.NewController(t)
		authenticator := NewMockAuthenticator(ctrl)
		authenticator.EXPECT().Authenticate(gomock.Any(), gomock.Any(), gomock.Any()).Return(expectedPeer, nil)
		cm := NewGRPCConnectionManager(Config{peerID: "server-peer-id"}, &stubNodeDIDReader{}, authenticator).(*grpcConnectionManager)
		defer cm.Stop()

		go cm.handleInboundStream(protocol, serverStream)
		test.WaitFor(t, func() (bool, error) {
			return len(cm.Peers()) == 1, nil
		}, 5*time.Second, "time-out while waiting for peer")

		peerInfo := cm.Peers()[0]
		assert.Equal(t, transport.PeerID("client-peer-id"), peerInfo.ID)
		assert.Equal(t, "127.0.0.1:9522", peerInfo.Address)
		assert.Equal(t, "did:nuts:client", peerInfo.NodeDID.String())
		// Assert headers sent to client
		assert.Equal(t, "server-peer-id", serverStream.sentHeaders.Get("peerID")[0])
		assert.Equal(t, "v1", serverStream.sentHeaders.Get("version")[0])
		assert.Equal(t, "did:nuts:test", serverStream.sentHeaders.Get("nodeDID")[0])

		// Assert connection was registered
		assert.Len(t, cm.connections.list, 1)
	})
	t.Run("authentication failed", func(t *testing.T) {
		expectedPeer := transport.Peer{
			ID:      "client-peer-id",
			Address: "127.0.0.1:9522",
			NodeDID: did.DID{},
		}
		clientDID, _ := did.ParseDID("did:nuts:client")
		expectedPeer.NodeDID = *clientDID
		serverStream := newServerStream(expectedPeer.ID, expectedPeer.NodeDID.String())
		ctrl := gomock.NewController(t)
		authenticator := NewMockAuthenticator(ctrl)
		authenticator.EXPECT().Authenticate(gomock.Any(), gomock.Any(), gomock.Any()).Return(expectedPeer, errors.New("failed"))
		cm := NewGRPCConnectionManager(Config{peerID: "server-peer-id"}, &stubNodeDIDReader{}, authenticator).(*grpcConnectionManager)

		err := cm.handleInboundStream(protocol, serverStream)
		assert.EqualError(t, err, "nodeDID authentication failed")
		assert.Empty(t, cm.connections.list)
	})
	t.Run("already connected client", func(t *testing.T) {
		cm := NewGRPCConnectionManager(Config{peerID: "server-peer-id"}, &stubNodeDIDReader{}, nil).(*grpcConnectionManager)
		defer cm.Stop()

		go cm.handleInboundStream(protocol, newServerStream("client-peer-id", ""))
		test.WaitFor(t, func() (bool, error) {
			return len(cm.Peers()) == 1, nil
		}, 5*time.Second, "time-out while waiting for peer")

		// Second connection with same peer ID is rejected
		err := cm.handleInboundStream(protocol, newServerStream("client-peer-id", ""))
		assert.ErrorIs(t, err, ErrAlreadyConnected)

		// Assert only first connection was registered
		assert.Len(t, cm.connections.list, 1)
	})
	t.Run("closing connection removes it from list", func(t *testing.T) {
		cm := NewGRPCConnectionManager(Config{peerID: "server-peer-id"}, &stubNodeDIDReader{}, nil).(*grpcConnectionManager)
		defer cm.Stop()

		stream := newServerStream("client-peer-id", "")
		go cm.handleInboundStream(protocol, stream)
		test.WaitFor(t, func() (bool, error) {
			return len(cm.Peers()) == 1, nil
		}, 5*time.Second, "time-out while waiting for peer")

		// Simulate a stream close
		stream.cancelFunc()

		test.WaitFor(t, func() (bool, error) {
			cm.connections.mux.Lock()
			defer cm.connections.mux.Unlock()
			return len(cm.connections.list) == 0, nil
		}, time.Second*2, "time-out while waiting for closed inbound connection to be removed")
	})
}

func Test_grpcConnectionManager_constructMetadata(t *testing.T) {
	t.Run("set default protocol version", func(t *testing.T) {
		cm := NewGRPCConnectionManager(Config{peerID: "server-peer-id"}, &stubNodeDIDReader{}, nil).(*grpcConnectionManager)
		md, _ := cm.constructMetadata()

		v := md.Get(protocolVersionHeader)

		assert.Len(t, v, 1)
		assert.Equal(t, protocolVersionV1, v[0])
	})
}

func newServerStream(clientPeerID transport.PeerID, nodeDID string) *stubServerStream {
	md := metadata.New(map[string]string{peerIDHeader: clientPeerID.String()})
	if nodeDID != "" {
		md.Set(nodeDIDHeader, nodeDID)
	}
	ctx := metadata.NewIncomingContext(context.Background(), md)
	ctx = peer.NewContext(ctx, &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: int(crc32.ChecksumIEEE([]byte(clientPeerID))%9000 + 1000)}})
	ctx = grpc.NewContextWithServerTransportStream(ctx, &stubServerTransportStream{method: "/unit/test"})
	ctx, cancelFunc := context.WithCancel(ctx)

	return &stubServerStream{
		ctx:        ctx,
		cancelFunc: cancelFunc,
	}
}

var nodeDID, _ = did.ParseDID("did:nuts:test")

type stubServerStream struct {
	sentHeaders metadata.MD
	cancelFunc  context.CancelFunc
	ctx         context.Context
}

func (s stubServerStream) SetHeader(md metadata.MD) error {
	panic("implement me")
}

func (s *stubServerStream) SendHeader(md metadata.MD) error {
	s.sentHeaders = md
	return nil
}

func (s stubServerStream) SetTrailer(md metadata.MD) {
	panic("implement me")
}

func (s stubServerStream) Context() context.Context {
	return s.ctx
}

func (s stubServerStream) SendMsg(m interface{}) error {
	panic("implement me")
}

func (s stubServerStream) RecvMsg(m interface{}) error {
	<-s.ctx.Done() // just block
	return io.EOF
}

type stubServerTransportStream struct {
	method string
}

func (s stubServerTransportStream) Method() string {
	return s.method
}

func (s stubServerTransportStream) SetHeader(md metadata.MD) error {
	panic("implement me")
}

func (s stubServerTransportStream) SendHeader(md metadata.MD) error {
	panic("implement me")
}

func (s stubServerTransportStream) SetTrailer(md metadata.MD) error {
	panic("implement me")
}

type stubNodeDIDReader struct {
}

func (s stubNodeDIDReader) Resolve() (did.DID, error) {
	return *nodeDID, nil
}
