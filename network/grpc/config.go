package grpc

import (
	"crypto/tls"
	"crypto/x509"
	"github.com/nuts-foundation/nuts-node/crl"
	networkTypes "github.com/nuts-foundation/nuts-node/network/protocol/types"
)

type Config struct {
	// PeerID contains the ID of the local node.
	PeerID networkTypes.PeerID
	// ListenAddress specifies the socket address the gRPC server should listen on.
	// If not set, the node will not accept incoming connections (but outbound connections can still be made).
	ListenAddress string
	// ServerCert specifies the TLS client certificate. If set the client should open a TLS socket, otherwise plain TCP.
	ClientCert tls.Certificate
	// ServerCert specifies the TLS server certificate. If set the server should open a TLS socket, otherwise plain TCP.
	ServerCert tls.Certificate
	// TrustStore contains the trust anchors used when verifying remote a peer's TLS certificate.
	TrustStore *x509.CertPool
	// CRLValidator contains the database for revoked certificates
	CRLValidator crl.Validator
	// MaxCRLValidityDays contains the number of days that a CRL can be outdated
	MaxCRLValidityDays int
}

func (cfg Config) tlsEnabled() bool {
	return cfg.TrustStore != nil
}
