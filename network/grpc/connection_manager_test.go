package grpc

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-node/crl"
	"github.com/nuts-foundation/nuts-node/network/protocol"
	"github.com/nuts-foundation/nuts-node/network/protocol/types"
	"github.com/nuts-foundation/nuts-node/test"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_grpcConnectionManager_Connect(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	p := protocol.NewMockProtocol(ctrl)
	cm := NewGRPCConnectionManager(Config{}, p)

	const expectedAddress = "foobar:1111"
	p.EXPECT().Connect(expectedAddress)
	cm.Connect(expectedAddress)
}

func Test_grpcConnectionManager_Peers(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	p := protocol.NewMockProtocol(ctrl)
	cm := NewGRPCConnectionManager(Config{}, p)

	expectedPeers := []types.Peer{{
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

		p := protocol.NewMockProtocol(ctrl)

		validator := crl.NewMockValidator(gomock.NewController(t))
		validator.EXPECT().SyncLoop(gomock.Any())
		validator.EXPECT().Configure(gomock.Any(), 10)

		cm := NewGRPCConnectionManager(Config{
			ListenAddress:      fmt.Sprintf(":%d", test.FreeTCPPort()),
			ClientCert:         tls.Certificate{},
			ServerCert:         tls.Certificate{},
			TrustStore:         x509.NewCertPool(),
			CRLValidator:       validator,
			MaxCRLValidityDays: 10,
		}, p)

		assert.NoError(t, cm.Start())
	})
}

func Test_grpcConnectionManager_acceptGRPCStream(t *testing.T) {
	// TODO
	//ctx := metadata.NewIncomingContext(peer.NewContext(context.Background(), &peer.Peer{
	//	Addr: &net.IPAddr{
	//		IP: net.IPv4(127, 0, 0, 1),
	//	},
	//}), metadata.Pairs(peerIDHeader, peerID))
	//conn.EXPECT().Context().AnyTimes().Return(ctx)
	//conn.EXPECT().SendHeader(gomock.Any())
}
