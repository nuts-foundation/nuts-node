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
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crl"
	networkTypes "github.com/nuts-foundation/nuts-node/network/transport"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
	"net"
)

func defaultListenerCreator(addr string) (net.Listener, error) {
	return net.Listen("tcp", addr)
}

// ConfigOption is used to build Config.
type ConfigOption func(config *Config)

// NewConfig creates a new Config, used for configuring a gRPC ConnectionManager.
func NewConfig(grpcAddress string, peerID networkTypes.PeerID, options ...ConfigOption) Config {
	cfg := Config{
		listenAddress: grpcAddress,
		peerID:        peerID,
		dialer:        grpc.DialContext,
		listener:      defaultListenerCreator,
	}
	for _, opt := range options {
		opt(&cfg)
	}
	return cfg
}

// NewBufconnConfig creates a new Config like NewConfig, but configures an in-memory bufconn listener instead of a TCP listener.
func NewBufconnConfig(peerID networkTypes.PeerID, options ...ConfigOption) (Config, *bufconn.Listener) {
	bufnet := bufconn.Listen(1024 * 1024)
	return NewConfig("bufnet", peerID, append(options[:], func(config *Config) {
		config.listener = func(_ string) (net.Listener, error) {
			return bufnet, nil
		}
	})...), bufnet
}

// WithTLS enables TLS for gRPC ConnectionManager.
func WithTLS(clientCertificate tls.Certificate, trustStore *core.TrustStore, maxCRLValidityDays int) ConfigOption {
	return func(config *Config) {
		config.clientCert = clientCertificate
		config.trustStore = trustStore.CertPool
		config.crlValidator = crl.NewValidator(trustStore.Certificates())
		config.maxCRLValidityDays = maxCRLValidityDays
		// Load TLS server certificate, only if enableTLS=true and gRPC server should be started.
		if config.listenAddress != "" {
			config.serverCert = config.clientCert
		}
	}
}

// WithBufconnDialer can be used to redirect outbound connections to a predetermined bufconn listener.
func WithBufconnDialer(listener *bufconn.Listener) ConfigOption {
	return func(config *Config) {
		config.dialer = func(ctx context.Context, target string, opts ...grpc.DialOption) (conn *grpc.ClientConn, err error) {
			return grpc.DialContext(ctx, "bufnet", grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
				return listener.Dial()
			}), grpc.WithInsecure())
		}
	}
}

// Config holds values for configuring the gRPC ConnectionManager.
type Config struct {
	// PeerID contains the ID of the local node.
	peerID networkTypes.PeerID
	// listenAddress specifies the socket address the gRPC server should listen on.
	// If not set, the node will not accept incoming connectionList (but outbound connectionList can still be made).
	listenAddress string
	// clientCert specifies the TLS client certificate. If set the client should open a TLS socket, otherwise plain TCP.
	clientCert tls.Certificate
	// serverCert specifies the TLS server certificate. If set the server should open a TLS socket, otherwise plain TCP.
	serverCert tls.Certificate
	// trustStore contains the trust anchors used when verifying remote a peer's TLS certificate.
	trustStore *x509.CertPool
	// crlValidator contains the database for revoked certificates
	crlValidator crl.Validator
	// maxCRLValidityDays contains the number of days that a CRL can be outdated
	maxCRLValidityDays int
	// listener holds a function to create the net.Listener that is used for inbound connections.
	listener func(string) (net.Listener, error)
	// dialer holds a function to open connections to remote gRPC services.
	dialer dialer
}

func (cfg Config) tlsEnabled() bool {
	return cfg.trustStore != nil
}
