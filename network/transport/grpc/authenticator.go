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
	"errors"
	"fmt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/nuts-foundation/nuts-node/vdr/service"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"net/url"
	"strings"
)

// Authenticator verifies node identities.
type Authenticator interface {
	// Authenticate verifies the given nodeDID using the given grpc.Peer.
	// When authentication is successful adds authenticated peer info to the given transport.Peer and returns it.
	// When authentication fails, an error is returned.
	Authenticate(nodeDID did.DID, peer transport.Peer) (transport.Peer, error)
}

// NewTLSAuthenticator creates an Authenticator that verifies node identities using TLS certificates.
func NewTLSAuthenticator(serviceResolver types.ServiceResolver) Authenticator {
	return &tlsAuthenticator{serviceResolver: serviceResolver}
}

type tlsAuthenticator struct {
	serviceResolver types.ServiceResolver
}

func (t tlsAuthenticator) Authenticate(nodeDID did.DID, peer transport.Peer) (transport.Peer, error) {
	// Resolve peer TLS certificate DNS names
	if peer.Certificate == nil {
		return peer, errors.New("missing TLS info")
	}

	// Resolve NutsComm endpoint of contained in DID document associated with node DID
	nutsCommService, err := t.serviceResolver.Resolve(service.MakeServiceReference(nodeDID, transport.NutsCommServiceType), service.DefaultMaxServiceReferenceDepth)
	var nutsCommURL *url.URL
	if err == nil {
		var nutsCommURLStr string
		_ = nutsCommService.UnmarshalServiceEndpoint(&nutsCommURLStr)
		nutsCommURL, err = url.Parse(nutsCommURLStr)
	}
	if err != nil {
		return peer, fmt.Errorf("can't resolve %s service: %w", transport.NutsCommServiceType, err)
	}

	// Check whether one of the DNS names matches one of the NutsComm endpoints
	err = peer.Certificate.VerifyHostname(nutsCommURL.Hostname())
	if err != nil {
		log.Logger().
			WithField(core.LogFieldDID, nodeDID).
			Debugf("DNS names: %s, peer certificate: %s", strings.Join(peer.Certificate.DNSNames, ", "), peer.CertificateAsPem())
		return peer, errors.New("none of the DNS names in the peer's TLS certificate match the NutsComm endpoint")
	}

	log.Logger().
		WithField(core.LogFieldDID, nodeDID).
		Debug("Connection successfully authenticated")
	peer.NodeDID = nodeDID
	peer.Authenticated = true
	return peer, nil
}

// NewDummyAuthenticator creates an Authenticator that does not verify node identities
func NewDummyAuthenticator(_ types.ServiceResolver) Authenticator {
	return &dummyAuthenticator{}
}

type dummyAuthenticator struct{}

func (d dummyAuthenticator) Authenticate(nodeDID did.DID, peer transport.Peer) (transport.Peer, error) {
	peer.NodeDID = nodeDID
	peer.Authenticated = true
	return peer, nil
}
