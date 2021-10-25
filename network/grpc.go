package network

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crl"
	"github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/network/protocol"
	networkTypes "github.com/nuts-foundation/nuts-node/network/protocol/types"
	"github.com/nuts-foundation/nuts-node/network/protocol/v1/p2p"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"net"
	"sync"
)


const defaultMaxMessageSizeInBytes = 1024 * 512

// MaxMessageSizeInBytes defines the maximum size of an in- or outbound gRPC/Protobuf message
var MaxMessageSizeInBytes = defaultMaxMessageSizeInBytes

type grpcConfig struct {
	// PeerID contains the ID of the local node.
	PeerID types.PeerID
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

func (cfg grpcConfig) tlsEnabled() bool {
	return cfg.TrustStore != nil
}


// TODO: Untangle from v1 and move to ConnectionManager/ManagedConnection
func buildGRPCConfig(moduleConfig Config, peerID networkTypes.PeerID) (*grpcConfig, error) {
	cfg := grpcConfig{
		ListenAddress: moduleConfig.GrpcAddr,
		PeerID:        peerID,
	}

	if moduleConfig.EnableTLS {
		clientCertificate, err := tls.LoadX509KeyPair(moduleConfig.CertFile, moduleConfig.CertKeyFile)
		if err != nil {
			return nil, errors.Wrapf(err, "unable to load node TLS client certificate (certfile=%s,certkeyfile=%s)", moduleConfig.CertFile, moduleConfig.CertKeyFile)
		}

		trustStore, err := core.LoadTrustStore(moduleConfig.TrustStoreFile)
		if err != nil {
			return nil, err
		}

		cfg.ClientCert = clientCertificate
		cfg.TrustStore = trustStore.CertPool
		cfg.MaxCRLValidityDays = moduleConfig.MaxCRLValidityDays
		cfg.CRLValidator = crl.NewValidator(trustStore.Certificates())

		// Load TLS server certificate, only if enableTLS=true and gRPC server should be started.
		if moduleConfig.GrpcAddr != "" {
			cfg.ServerCert = cfg.ClientCert
		}
	} else {
		log.Logger().Info("TLS is disabled, make sure the Nuts Node is behind a TLS terminator which performs TLS authentication.")
	}

	return &cfg, nil
}


// newGRPCConnectionManager creates a new ConnectionManager that accepts/creates connections which communicate using the given protocols.
func newGRPCConnectionManager(config grpcConfig, protocols ...protocol.Protocol) ConnectionManager {
	if len(protocols) > 1 {
		// TODO: Support multiple protocol versions
		panic("ConnectionManager: multiple protocols currently not supported")
	}
	return &grpcConnectionManager{
		protocols:       protocols,
		config:          config,
		grpcServerMutex: &sync.Mutex{},
	}
}

// grpcConnectionManager is a ConnectionManager that does not discover peers on its own, but just connects to the peers for which Connect() is called.
type grpcConnectionManager struct {
	protocols []protocol.Protocol
	config    grpcConfig

	grpcServer      *grpc.Server
	grpcServerMutex *sync.Mutex
	listener        net.Listener
}

func (s grpcConnectionManager) Start() error {
	s.grpcServerMutex.Lock()
	defer s.grpcServerMutex.Unlock()

	if s.config.ListenAddress != "" {
		log.Logger().Infof("Starting gRPC server on %s", s.config.ListenAddress)
		serverOpts := []grpc.ServerOption{
			grpc.MaxRecvMsgSize(MaxMessageSizeInBytes),
			grpc.MaxSendMsgSize(MaxMessageSizeInBytes),
		}
		var err error
		s.listener, err = net.Listen("tcp", s.config.ListenAddress)
		if err != nil {
			return err
		}
		// Set ListenAddress to actual interface address resolved by `Listen()`
		s.config.ListenAddress = s.listener.Addr().String()
		// Configure TLS if enabled
		if s.config.tlsEnabled() {
			serverOpts = append(serverOpts, grpc.Creds(credentials.NewTLS(&tls.Config{
				Certificates: []tls.Certificate{s.config.ServerCert},
				ClientAuth:   tls.RequireAndVerifyClientCert,
				ClientCAs:    s.config.TrustStore,
			})))
		}

		if s.config.CRLValidator != nil {
			s.config.CRLValidator.SyncLoop(context.TODO())
		}
		// Configure support for checking revoked certificates
		s.config.CRLValidator.Configure(tlsConfig, s.config.MaxCRLValidityDays)

		s.grpcServer = grpc.NewServer(serverOpts...)
		for _, prot := range s.protocols {
			grpcProtocol, ok := prot.(protocol.GRPCServiceProvider)
			if ok {
				grpcProtocol.RegisterService(s)
			}
		}
		go func(server *grpc.Server, listener net.Listener) {
			err := server.Serve(listener)
			if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
				log.Logger().Errorf("gRPC server errored: %v", err)
				s.Stop()
			}
		}(s.grpcServer, s.listener)
	} else {
		log.Logger().Info("Not starting gRPC server, connections will only be outbound.")
	}
	return nil
}

func (s grpcConnectionManager) Stop() {
	s.grpcServerMutex.Lock()
	defer s.grpcServerMutex.Unlock()

	// Stop gRPC server
	if s.grpcServer != nil {
		s.grpcServer.Stop()
		s.grpcServer = nil
	}
	// Stop TCP listener
	if s.listener != nil {
		if err := s.listener.Close(); err != nil {
			log.Logger().Warn("Error while closing server listener: ", err)
		}
		s.listener = nil
	}
}

func (s grpcConnectionManager) Connect(peerAddress string) {
	s.protocols[0].Connect(peerAddress)
}

func (s grpcConnectionManager) Peers() []types.Peer {
	return s.protocols[0].Peers()
}

// RegisterService implements grpc.ServiceRegistrar to register the gRPC services protocols expose.
func (s grpcConnectionManager) RegisterService(desc *grpc.ServiceDesc, impl interface{}) {
	s.grpcServer.RegisterService(desc, impl)
}
