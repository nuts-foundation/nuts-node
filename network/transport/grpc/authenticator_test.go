package grpc

import (
	"crypto/tls"
	"crypto/x509"
	"github.com/golang/mock/gomock"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/nuts-foundation/nuts-node/vdr/doc"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"os"
	"testing"
)

func Test_tlsAuthenticator_Authenticate(t *testing.T) {
	data, _ := os.ReadFile("test/nuts.nl.cer")
	cert, _ := x509.ParseCertificate(data)
	grpcPeer := peer.Peer{
		AuthInfo: credentials.TLSInfo{
			State:          tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{cert},
			},
		},
	}

	nodeDID := *nodeDID
	query, _ := ssi.ParseURI(nodeDID.String() + "/serviceEndpoint?type=NutsComm")

	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		serviceResolver := doc.NewMockServiceResolver(ctrl)
		serviceResolver.EXPECT().Resolve(*query, gomock.Any()).Return(did.Service{ServiceEndpoint: "grpc://nuts.nl:5555"}, nil)
		authenticator := NewTLSAuthenticator(serviceResolver)
		grpcPeer := peer.Peer{
			AuthInfo: credentials.TLSInfo{
				State:          tls.ConnectionState{
					PeerCertificates: []*x509.Certificate{cert},
				},
			},
		}

		authenticatedPeer, err := authenticator.Authenticate(nodeDID, grpcPeer, transport.Peer{})

		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, authenticatedPeer.NodeDID, nodeDID)
	})
	t.Run("not authenticated, DNS names do not match", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		serviceResolver := doc.NewMockServiceResolver(ctrl)
		serviceResolver.EXPECT().Resolve(*query, gomock.Any()).Return(did.Service{ServiceEndpoint: "grpc://nootjes.nl:5555"}, nil)
		authenticator := NewTLSAuthenticator(serviceResolver)

		authenticatedPeer, err := authenticator.Authenticate(nodeDID, grpcPeer, transport.Peer{})

		assert.EqualError(t, err, "none of the DNS names in the peer's TLS certificate match the NutsComm endpoint (nodeDID=did:nuts:test)")
		assert.Empty(t, authenticatedPeer)
	})
	t.Run("no TLS info", func(t *testing.T) {
		authenticatedPeer, err := NewTLSAuthenticator(nil).Authenticate(nodeDID, peer.Peer{}, transport.Peer{})
		assert.EqualError(t, err, "missing TLS info (nodeDID=did:nuts:test)")
		assert.Empty(t, authenticatedPeer)
	})
	t.Run("DID document not found", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		serviceResolver := doc.NewMockServiceResolver(ctrl)
		serviceResolver.EXPECT().Resolve(*query, gomock.Any()).Return(did.Service{}, types.ErrNotFound)
		authenticator := NewTLSAuthenticator(serviceResolver)

		authenticatedPeer, err := authenticator.Authenticate(nodeDID, grpcPeer, transport.Peer{})

		assert.EqualError(t, err, "can't resolve NutsComm service (nodeDID=did:nuts:test): unable to find the DID document")
		assert.Empty(t, authenticatedPeer)
	})
}
