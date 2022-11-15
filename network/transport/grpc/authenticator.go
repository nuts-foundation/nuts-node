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
	"fmt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/nuts-foundation/nuts-node/vdr/doc"
	"google.golang.org/grpc/credentials"
	grpcPeer "google.golang.org/grpc/peer"
	"net/url"
	"strings"
)

// Authenticator verifies node identities.
type Authenticator interface {
	// Authenticate verifies the given nodeDID using the given grpc.Peer.
	// When authentication is successful adds authenticated peer info to the given transport.Peer and returns it.
	// When authentication fails, an error is returned.
	Authenticate(nodeDID did.DID, grpcPeer grpcPeer.Peer, peer transport.Peer) (transport.Peer, error)
	// AuthenticateNodeDID verifies that the certificate matches the NutsComm address in the nodeDID.
	// When authentication fails, an error is returned.
	AuthenticateNodeDID(nodeDID did.DID, certificate x509.Certificate) error
}

// NewTLSAuthenticator creates an Authenticator that verifies node identities using TLS certificates.
func NewTLSAuthenticator(serviceResolver doc.ServiceResolver) Authenticator {
	return &tlsAuthenticator{serviceResolver: serviceResolver}
}

type tlsAuthenticator struct {
	serviceResolver doc.ServiceResolver
}

func (t tlsAuthenticator) Authenticate(nodeDID did.DID, grpcPeer grpcPeer.Peer, peer transport.Peer) (transport.Peer, error) {
	withOverride := func(peer transport.Peer, err error) (transport.Peer, error) {
		if peer.AcceptUnauthenticated {
			log.Logger().
				WithError(err).
				WithField(core.LogFieldDID, nodeDID).
				Warn("Connection manually authenticated with authentication error")
			peer.NodeDID = nodeDID
			return peer, nil
		}
		return peer, err
	}

	// Resolve peer TLS certificate DNS names
	tlsInfo, isTLS := grpcPeer.AuthInfo.(credentials.TLSInfo)
	if !isTLS || len(tlsInfo.State.PeerCertificates) == 0 {
		return withOverride(peer, fmt.Errorf("missing TLS info (nodeDID=%s)", nodeDID))
	}
	peerCertificate := tlsInfo.State.PeerCertificates[0]

	if err := t.AuthenticateNodeDID(nodeDID, *peerCertificate); err != nil {
		return withOverride(peer, err)
	}

	log.Logger().
		WithField(core.LogFieldDID, nodeDID).
		Debug("Connection successfully authenticated")
	peer.NodeDID = nodeDID
	return peer, nil
}

func (t tlsAuthenticator) AuthenticateNodeDID(nodeDID did.DID, certificate x509.Certificate) error {
	// Resolve NutsComm endpoint of contained in DID document associated with node DID
	nutsCommService, err := t.serviceResolver.Resolve(doc.MakeServiceReference(nodeDID, transport.NutsCommServiceType), doc.DefaultMaxServiceReferenceDepth)
	var nutsCommURL *url.URL
	if err == nil {
		var nutsCommURLStr string
		_ = nutsCommService.UnmarshalServiceEndpoint(&nutsCommURLStr)
		nutsCommURL, err = url.Parse(nutsCommURLStr)
	}
	if err != nil {
		return fmt.Errorf("can't resolve %s service (nodeDID=%s): %w", transport.NutsCommServiceType, nodeDID, err)
	}

	// Check whether one of the DNS names matches one of the NutsComm endpoints
	err = certificate.VerifyHostname(nutsCommURL.Hostname())
	if err != nil {
		log.Logger().
			WithField(core.LogFieldDID, nodeDID).
			Debugf("DNS names in peer certificate: %s", strings.Join(certificate.DNSNames, ", "))
		return fmt.Errorf("none of the DNS names in the TLS certificate match the %s endpoint (nodeDID=%s)", transport.NutsCommServiceType, nodeDID)
	}
	return nil
}

// NewDummyAuthenticator creates an Authenticator that does not verify node identities
func NewDummyAuthenticator(serviceResolver doc.ServiceResolver) Authenticator {
	return &dummyAuthenticator{}
}

type dummyAuthenticator struct{}

func (d dummyAuthenticator) Authenticate(nodeDID did.DID, grpcPeer grpcPeer.Peer, peer transport.Peer) (transport.Peer, error) {
	peer.NodeDID = nodeDID
	return peer, nil
}

func (d dummyAuthenticator) AuthenticateNodeDID(nodeDID did.DID, certificate x509.Certificate) error {
	return nil
}
