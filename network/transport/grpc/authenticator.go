package grpc

import (
	"fmt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/nuts-foundation/nuts-node/vdr/doc"
	"google.golang.org/grpc/credentials"
	grpcPeer "google.golang.org/grpc/peer"
	"net/url"
)

const nutsCommServiceType = "NutsComm"

// Authenticator verifies node identities.
type Authenticator interface {
	// Authenticate verifies the given nodeDID using the given grpc.Peer.
	// When authentication is successful adds authenticated peer info to the given transport.Peer and returns it.
	// When authentication fails, an error is returned.
	Authenticate(nodeDID did.DID, grpcPeer grpcPeer.Peer, peer transport.Peer) (transport.Peer, error)
}

// NewTLSAuthenticator creates an Authenticator that verifies node identities using TLS certificates.
func NewTLSAuthenticator(serviceResolver doc.ServiceResolver) Authenticator {
	return &tlsAuthenticator{serviceResolver: serviceResolver}
}

type tlsAuthenticator struct {
	serviceResolver doc.ServiceResolver
}

func (t tlsAuthenticator) Authenticate(nodeDID did.DID, grpcPeer grpcPeer.Peer, peer transport.Peer) (transport.Peer, error) {
	// Resolve peer TLS certificate DNS names
	tlsInfo, isTLS := grpcPeer.AuthInfo.(credentials.TLSInfo)
	if !isTLS || len(tlsInfo.State.PeerCertificates) == 0 {
		return peer, fmt.Errorf("missing TLS info (nodeDID=%s)", nodeDID)
	}
	dnsNames := tlsInfo.State.PeerCertificates[0].DNSNames

	// Resolve NutsComm endpoint of contained in DID document associated with node DID
	nutsCommService, err := t.serviceResolver.ResolveService(doc.MakeServiceReference(nodeDID, nutsCommServiceType), 3)
	var nutsCommURL *url.URL
	if err == nil {
		var nutsCommURLStr string
		_ = nutsCommService.UnmarshalServiceEndpoint(&nutsCommURLStr)
		nutsCommURL, err = url.Parse(nutsCommURLStr)
	}
	if err != nil {
		return peer, fmt.Errorf("can't resolve %s service (nodeDID=%s): %w", nutsCommServiceType, nodeDID, err)
	}

	// Check whether one of the DNS names matches one of the NutsComm endpoints
	hostname := nutsCommURL.Hostname()
	for _, dnsName := range dnsNames {
		if dnsName == hostname {
			log.Logger().Debugf("Connection successfully authenticated (nodeDID=%s)", nodeDID)
			peer.NodeDID = nodeDID
			return peer, nil
		}
	}
	return peer, fmt.Errorf("none of the DNS names in the peer's TLS certificate match the NutsComm endpoint (nodeDID=%s)", nodeDID)
}
