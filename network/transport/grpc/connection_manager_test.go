package grpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-node/crl"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/nuts-foundation/nuts-node/test"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"net"
	"testing"
)

func Test_grpcConnectionManager_Connect(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	p := transport.NewMockProtocol(ctrl)
	cm := NewGRPCConnectionManager(Config{}, p)

	const expectedAddress = "foobar:1111"
	p.EXPECT().Connect(expectedAddress)
	cm.Connect(expectedAddress)
}

func Test_grpcConnectionManager_Peers(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	p := transport.NewMockProtocol(ctrl)
	cm := NewGRPCConnectionManager(Config{}, p)

	expectedPeers := []transport.Peer{{
		ID:      "1",
		Address: "foobar",
	}}
	p.EXPECT().Peers().Return(expectedPeers)
	assert.Equal(t, expectedPeers, cm.Peers())
}

func Test_grpcConnectionManager_Start(t *testing.T) {
	t.Run("ok - gRPC server not bound", func(t *testing.T) {
		cm := NewGRPCConnectionManager(Config{}).(*grpcConnectionManager)
		assert.NoError(t, cm.Start())
		assert.Nil(t, cm.listener)
	})
	t.Run("ok - gRPC server bound, TLS enabled", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		validator := crl.NewMockValidator(gomock.NewController(t))
		validator.EXPECT().SyncLoop(gomock.Any())
		validator.EXPECT().Configure(gomock.Any(), gomock.Any())

		serverCert, _ := tls.LoadX509KeyPair("../../test/certificate-and-key.pem", "../../test/certificate-and-key.pem")
		cm := NewGRPCConnectionManager(Config{
			PeerID:        "foo",
			ListenAddress: fmt.Sprintf("127.0.0.1:%d", test.FreeTCPPort()),
			ServerCert:    serverCert,
			TrustStore:    x509.NewCertPool(),
			CRLValidator:  validator,
		}).(*grpcConnectionManager)
		err := cm.Start()
		if !assert.NoError(t, err) {
			return
		}
		defer cm.Stop()

		assert.NotNil(t, cm.listener)
	})
	t.Run("ok - gRPC server bound, TLS disabled", func(t *testing.T) {
		cm := NewGRPCConnectionManager(Config{
			PeerID:        "foo",
			ListenAddress: fmt.Sprintf("127.0.0.1:%d", test.FreeTCPPort()),
		}).(*grpcConnectionManager)
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

		p := transport.NewMockProtocol(ctrl)

		validator := crl.NewMockValidator(gomock.NewController(t))
		validator.EXPECT().SyncLoop(gomock.Any())
		validator.EXPECT().Configure(gomock.Any(), 10)

		cm := NewGRPCConnectionManager(Config{
			ListenAddress:      fmt.Sprintf(":%d", test.FreeTCPPort()),
			TrustStore:         x509.NewCertPool(),
			CRLValidator:       validator,
			MaxCRLValidityDays: 10,
		}, p)

		assert.NoError(t, cm.Start())
		cm.Stop()
	})
}

func Test_grpcConnectionManager_acceptGRPCStream(t *testing.T) {
	t.Run("new client", func(t *testing.T) {
		cm := NewGRPCConnectionManager(Config{PeerID: "server-peer-id"}).(*grpcConnectionManager)

		serverStream := &stubServerStream{clientMetadata: constructMetadata("client-peer-id")}
		accepted, peerInfo, closer := cm.acceptGRPCStream(serverStream)

		assert.True(t, accepted) // not already connected
		assert.Equal(t, transport.PeerID("client-peer-id"), peerInfo.ID)
		assert.Equal(t, "127.0.0.1", peerInfo.Address)
		assert.NotNil(t, closer)
		// Assert headers sent to client
		assert.Equal(t, "server-peer-id", serverStream.sentHeaders.Get("peerID")[0])
		assert.Equal(t, "v1", serverStream.sentHeaders.Get("version")[0])

		// Assert connection was registered
		assert.Len(t, cm.connections.list, 1)
	})
	t.Run("already connected client", func(t *testing.T) {
		cm := NewGRPCConnectionManager(Config{PeerID: "server-peer-id"}).(*grpcConnectionManager)

		serverStream1 := &stubServerStream{clientMetadata: constructMetadata("client-peer-id")}
		accepted, _, _ := cm.acceptGRPCStream(serverStream1)
		assert.True(t, accepted)

		// Second connection with same peer ID is rejected
		serverStream2 := &stubServerStream{clientMetadata: constructMetadata("client-peer-id")}
		accepted2, _, _ := cm.acceptGRPCStream(serverStream2)
		assert.False(t, accepted2)

		// Assert only first connection was registered
		assert.Len(t, cm.connections.list, 1)
	})
}

type stubServerStream struct {
	clientMetadata metadata.MD
	sentHeaders    metadata.MD
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
	ctx := context.Background()
	ctx = metadata.NewIncomingContext(ctx, s.clientMetadata)
	ctx = peer.NewContext(ctx, &peer.Peer{Addr: &net.IPAddr{IP: net.ParseIP("127.0.0.1")}})
	return ctx
}

func (s stubServerStream) SendMsg(m interface{}) error {
	panic("implement me")
}

func (s stubServerStream) RecvMsg(m interface{}) error {
	panic("implement me")
}
