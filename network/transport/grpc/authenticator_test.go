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
	"crypto/x509"
	"github.com/nuts-foundation/nuts-node/vdr/didservice"
	"github.com/stretchr/testify/require"
	"os"
	"testing"

	"github.com/golang/mock/gomock"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/stretchr/testify/assert"
)

func Test_tlsAuthenticator_Authenticate(t *testing.T) {
	certData, _ := os.ReadFile("test/nuts.nl.cer")
	cert, _ := x509.ParseCertificate(certData)
	wildcardCertData, _ := os.ReadFile("test/wildcard.nuts.nl.cer")
	wildcardCert, _ := x509.ParseCertificate(wildcardCertData)

	nodeDID := *nodeDID
	query := ssi.MustParseURI(nodeDID.String() + "/serviceEndpoint?type=NutsComm")
	expectedPeer := transport.Peer{
		NodeDID:       nodeDID,
		Authenticated: true,
		Certificate:   cert,
	}

	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		serviceResolver := didservice.NewMockServiceResolver(ctrl)
		serviceResolver.EXPECT().Resolve(query, gomock.Any()).Return(did.Service{ServiceEndpoint: "grpc://nuts.nl:5555"}, nil)
		authenticator := NewTLSAuthenticator(serviceResolver)

		authenticatedPeer, err := authenticator.Authenticate(nodeDID, transport.Peer{Certificate: cert})

		require.NoError(t, err)
		assert.Equal(t, expectedPeer, authenticatedPeer)
	})
	t.Run("ok - case insensitive comparison", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		serviceResolver := didservice.NewMockServiceResolver(ctrl)
		serviceResolver.EXPECT().Resolve(query, gomock.Any()).Return(did.Service{ServiceEndpoint: "grpc://Nuts.nl:5555"}, nil)
		authenticator := NewTLSAuthenticator(serviceResolver)

		authenticatedPeer, err := authenticator.Authenticate(nodeDID, transport.Peer{Certificate: cert})

		require.NoError(t, err)
		assert.Equal(t, expectedPeer, authenticatedPeer)
	})
	t.Run("ok - wildcard comparison", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		serviceResolver := didservice.NewMockServiceResolver(ctrl)
		serviceResolver.EXPECT().Resolve(query, gomock.Any()).Return(did.Service{ServiceEndpoint: "grpc://node.nuts.nl:5555"}, nil)
		authenticator := NewTLSAuthenticator(serviceResolver)
		expectedPeer := transport.Peer{
			NodeDID:       nodeDID,
			Authenticated: true,
			Certificate:   wildcardCert,
		}

		authenticatedPeer, err := authenticator.Authenticate(nodeDID, transport.Peer{Certificate: wildcardCert})

		require.NoError(t, err)
		assert.Equal(t, expectedPeer, authenticatedPeer)
	})
	t.Run("authentication fails", func(t *testing.T) {
		transportPeer := transport.Peer{ID: "peer", Certificate: cert}
		t.Run("DNS names do not match", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			serviceResolver := didservice.NewMockServiceResolver(ctrl)
			serviceResolver.EXPECT().Resolve(query, gomock.Any()).Return(did.Service{ServiceEndpoint: "grpc://nootjes.nl:5555"}, nil)
			authenticator := NewTLSAuthenticator(serviceResolver)

			authenticatedPeer, err := authenticator.Authenticate(nodeDID, transportPeer)

			assert.EqualError(t, err, "none of the DNS names in the peer's TLS certificate match the NutsComm endpoint")
			assert.Equal(t, transportPeer, authenticatedPeer)
		})
		t.Run("no TLS info", func(t *testing.T) {
			transportPeer := transport.Peer{ID: "peer"}
			authenticatedPeer, err := NewTLSAuthenticator(nil).Authenticate(nodeDID, transportPeer)
			assert.EqualError(t, err, "missing TLS info")
			assert.Equal(t, transportPeer, authenticatedPeer)
		})
		t.Run("DID document not found", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			serviceResolver := didservice.NewMockServiceResolver(ctrl)
			serviceResolver.EXPECT().Resolve(query, gomock.Any()).Return(did.Service{}, types.ErrNotFound)
			authenticator := NewTLSAuthenticator(serviceResolver)

			authenticatedPeer, err := authenticator.Authenticate(nodeDID, transportPeer)

			assert.EqualError(t, err, "can't resolve NutsComm service: unable to find the DID document")
			assert.Equal(t, transportPeer, authenticatedPeer)
		})
	})
}

func TestDummyAuthenticator_Authenticate(t *testing.T) {
	t.Run("always ok", func(t *testing.T) {
		authenticator := NewDummyAuthenticator(nil)

		peer, err := authenticator.Authenticate(*nodeDID, transport.Peer{})

		assert.NoError(t, err)
		assert.Equal(t, *nodeDID, peer.NodeDID)
		assert.True(t, peer.Authenticated)
	})
}
