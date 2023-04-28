/*
 * Copyright (C) 2023 Nuts community
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
	"errors"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/pki"
        pkiconfig "github.com/nuts-foundation/nuts-node/pki/config"
	networkTypes "github.com/nuts-foundation/nuts-node/network/transport"
	"google.golang.org/grpc"
	"net"
	"time"
)

// tcpListenerCreator starts a TCP listener for the inbound gRPC server on the given address.
// It's used by default when running the Nuts node, but unit tests can use an alternative listener creator (e.g. bufconn for in-memory channels).
func tcpListenerCreator(addr string) (net.Listener, error) {
	return net.Listen("tcp", addr)
}

// ConfigOption is used to build Config.
type ConfigOption func(config *Config) error

// NewConfig creates a new Config, used for configuring a gRPC ConnectionManager.
func NewConfig(grpcAddress string, peerID networkTypes.PeerID, options ...ConfigOption) (Config, error) {
	cfg := Config{
		listenAddress:     grpcAddress,
		peerID:            peerID,
		dialer:            grpc.DialContext,
		listener:          tcpListenerCreator,
		connectionTimeout: 5 * time.Second,
		backoffCreator: func() Backoff {
			return BoundedBackoff(time.Second, time.Hour)
		},
	}
	for _, opt := range options {
		if err := opt(&cfg); err != nil {
			return Config{}, err
		}
	}
	return cfg, nil
}

// WithTLS enables TLS for gRPC ConnectionManager.
func WithTLS(clientCertificate tls.Certificate, trustStore *core.TrustStore) ConfigOption {
	return func(config *Config) error {
		config.clientCert = &clientCertificate
		config.trustStore = trustStore.CertPool
		
		pkiCfg := pkiconfig.Config{
			MaxUpdateFailHours: 4,
		}
		crlValidator, err := pki.NewValidator(pkiCfg, trustStore.Certificates())
		if err != nil {
			return err
		}
		config.crlValidator = crlValidator
		// Load TLS server certificate, only if enableTLS=true and gRPC server should be started.
		if config.listenAddress != "" {
			config.serverCert = config.clientCert
		}
		return nil
	}
}

// WithTLSOffloading enables TLS for outgoing connections, but is offloaded for incoming connections.
// It MUST be used in conjunction, but after with WithTLS.
func WithTLSOffloading(clientCertHeaderName string) ConfigOption {
	return func(config *Config) error {
		if clientCertHeaderName == "" {
			return errors.New("tls.certheader must be configured to enable TLS offloading ")
		}
		config.clientCertHeaderName = clientCertHeaderName
		config.serverCert = nil
		return nil
	}
}

// WithConnectionTimeout specifies the connection timeout for outbound connection attempts.
func WithConnectionTimeout(value time.Duration) ConfigOption {
	return func(config *Config) error {
		config.connectionTimeout = value
		return nil
	}
}

func WithBackoff(value func() Backoff) ConfigOption {
	return func(config *Config) error {
		config.backoffCreator = value
		return nil
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
	clientCert *tls.Certificate
	// serverCert specifies the TLS server certificate. If set the server should open a TLS socket, otherwise plain TCP.
	serverCert *tls.Certificate
	// trustStore contains the trust anchors used when verifying remote a peer's TLS certificate.
	trustStore *x509.CertPool
	// crlValidator contains the database for revoked certificates
	crlValidator pki.Validator
	// clientCertHeaderName specifies the name of the HTTP header that contains the client certificate, if TLS is offloaded.
	clientCertHeaderName string
	// connectionTimeout specifies the time before an outbound connection attempt times out.
	connectionTimeout time.Duration
	// listener holds a function to create the net.Listener that is used for inbound connections.
	listener func(string) (net.Listener, error)
	// dialer holds a function to open connections to remote gRPC services.
	dialer dialer
	// backoffCreator holds a function that creates a Backoff.
	backoffCreator func() Backoff
}

func (cfg Config) tlsEnabled() bool {
	return cfg.trustStore != nil
}

func newServerTLSConfig(config Config) (*tls.Config, error) {
	tlsConfig, err := newTLSConfig(config)
	if err != nil {
		return nil, err
	}
	tlsConfig.ClientCAs = config.trustStore
	tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	tlsConfig.Certificates = []tls.Certificate{
		*config.serverCert,
	}
	return tlsConfig, nil
}

func newClientTLSConfig(config Config) (*tls.Config, error) {
	tlsConfig, err := newTLSConfig(config)
	if err != nil {
		return nil, err
	}
	tlsConfig.RootCAs = config.trustStore
	tlsConfig.Certificates = []tls.Certificate{
		*config.clientCert,
	}
	return tlsConfig, nil
}

func newTLSConfig(config Config) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion: core.MinTLSVersion,
	}

	if err := config.crlValidator.SetValidatePeerCertificateFunc(tlsConfig); err != nil {
		// cannot fail
		return nil, err
	}

	return tlsConfig, nil
}
