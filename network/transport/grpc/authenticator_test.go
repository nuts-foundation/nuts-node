/*
 * Copyright (C) 2022 Nuts community
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
	"crypto/tls"
	"crypto/x509"
	"os"
	"testing"

	"github.com/golang/mock/gomock"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/nuts-foundation/nuts-node/vdr/doc"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

func Test_tlsAuthenticator_Authenticate(t *testing.T) {
	data, _ := os.ReadFile("test/nuts.nl.cer")
	cert, _ := x509.ParseCertificate(data)
	grpcPeer := peer.Peer{
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
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
				State: tls.ConnectionState{
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
	t.Run("without acceptUnauthenticated", func(t *testing.T) {
		transportPeer := transport.Peer{}
		t.Run("not authenticated, DNS names do not match", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			serviceResolver := doc.NewMockServiceResolver(ctrl)
			serviceResolver.EXPECT().Resolve(*query, gomock.Any()).Return(did.Service{ServiceEndpoint: "grpc://nootjes.nl:5555"}, nil)
			authenticator := NewTLSAuthenticator(serviceResolver)

			authenticatedPeer, err := authenticator.Authenticate(nodeDID, grpcPeer, transportPeer)

			assert.EqualError(t, err, "none of the DNS names in the peer's TLS certificate match the NutsComm endpoint (nodeDID=did:nuts:test)")
			assert.Empty(t, authenticatedPeer)
		})
		t.Run("no TLS info", func(t *testing.T) {
			authenticatedPeer, err := NewTLSAuthenticator(nil).Authenticate(nodeDID, peer.Peer{}, transportPeer)
			assert.EqualError(t, err, "missing TLS info (nodeDID=did:nuts:test)")
			assert.Empty(t, authenticatedPeer)
		})
		t.Run("DID document not found", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			serviceResolver := doc.NewMockServiceResolver(ctrl)
			serviceResolver.EXPECT().Resolve(*query, gomock.Any()).Return(did.Service{}, types.ErrNotFound)
			authenticator := NewTLSAuthenticator(serviceResolver)

			authenticatedPeer, err := authenticator.Authenticate(nodeDID, grpcPeer, transportPeer)

			assert.EqualError(t, err, "can't resolve NutsComm service (nodeDID=did:nuts:test): unable to find the DID document")
			assert.Empty(t, authenticatedPeer)
		})
	})
	t.Run("with acceptUnauthenticated", func(t *testing.T) {
		transportPeer := transport.Peer{AcceptUnauthenticated: true}
		t.Run("not authenticated, DNS names do not match", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			serviceResolver := doc.NewMockServiceResolver(ctrl)
			serviceResolver.EXPECT().Resolve(*query, gomock.Any()).Return(did.Service{ServiceEndpoint: "grpc://nootjes.nl:5555"}, nil)
			authenticator := NewTLSAuthenticator(serviceResolver)

			authenticatedPeer, err := authenticator.Authenticate(nodeDID, grpcPeer, transportPeer)

			assert.NoError(t, err)
			assert.Equal(t, transportPeer, authenticatedPeer)
		})
		t.Run("no TLS info", func(t *testing.T) {
			authenticatedPeer, err := NewTLSAuthenticator(nil).Authenticate(nodeDID, peer.Peer{}, transportPeer)
			assert.NoError(t, err)
			assert.Equal(t, transportPeer, authenticatedPeer)
		})
		t.Run("DID document not found", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			serviceResolver := doc.NewMockServiceResolver(ctrl)
			serviceResolver.EXPECT().Resolve(*query, gomock.Any()).Return(did.Service{}, types.ErrNotFound)
			authenticator := NewTLSAuthenticator(serviceResolver)

			authenticatedPeer, err := authenticator.Authenticate(nodeDID, grpcPeer, transportPeer)

			assert.NoError(t, err)
			assert.Equal(t, transportPeer, authenticatedPeer)
		})
	})
}

func TestDummyAuthenticator_Authenticate(t *testing.T) {
	t.Run("always ok", func(t *testing.T) {
		authenticator := NewDummyAuthenticator(nil)

		peer, err := authenticator.Authenticate(*nodeDID, peer.Peer{}, transport.Peer{})

		assert.NoError(t, err)
		assert.Equal(t, *nodeDID, peer.NodeDID)
	})
}
