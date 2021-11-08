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
	"fmt"
	"github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	grpcPeer "google.golang.org/grpc/peer"
	"net"
	"sync"
)

const defaultMaxMessageSizeInBytes = 1024 * 512

const protocolVersionV1 = "v1"          // required for backwards compatibility with v1
const protocolVersionHeader = "version" // required for backwards compatibility with v1
const peerIDHeader = "peerID"

// ErrAlreadyConnected indicates the node is already connected to the peer.
var ErrAlreadyConnected = errors.New("already connected")

// MaxMessageSizeInBytes defines the maximum size of an in- or outbound gRPC/Protobuf message
var MaxMessageSizeInBytes = defaultMaxMessageSizeInBytes

// NewGRPCConnectionManager creates a new ConnectionManager that accepts/creates connections which communicate using the given protocols.
func NewGRPCConnectionManager(config Config, protocols ...transport.Protocol) transport.ConnectionManager {
	if len(protocols) > 1 {
		// TODO: Support multiple protocol versions
		panic("ConnectionManager: multiple protocols currently not supported")
	}
	return &grpcConnectionManager{
		protocols:       protocols,
		config:          config,
		connections:     &connectionList{},
		grpcServerMutex: &sync.Mutex{},
		listenerCreator: config.listener,
		dialer:          config.dialer,
	}
}

// grpcConnectionManager is a ConnectionManager that does not discover peers on its own, but just connects to the peers for which Connect() is called.
type grpcConnectionManager struct {
	protocols       []transport.Protocol
	config          Config
	connections     *connectionList
	grpcServer      *grpc.Server
	grpcServerMutex *sync.Mutex
	listener        net.Listener
	listenerCreator func(string) (net.Listener, error)
	dialer          dialer
}

func (s *grpcConnectionManager) Start() error {
	s.grpcServerMutex.Lock()
	defer s.grpcServerMutex.Unlock()

	if s.config.listenAddress == "" {
		log.Logger().Info("Not starting gRPC server, connections will only be outbound.")
		return nil
	}

	log.Logger().Debugf("Starting gRPC server on %s", s.config.listenAddress)
	serverOpts := []grpc.ServerOption{
		grpc.MaxRecvMsgSize(MaxMessageSizeInBytes),
		grpc.MaxSendMsgSize(MaxMessageSizeInBytes),
	}
	var err error
	s.listener, err = s.listenerCreator(s.config.listenAddress)
	if err != nil {
		return err
	}
	// Configure TLS if enabled
	if s.config.tlsEnabled() {
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{s.config.serverCert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    s.config.trustStore,
		}
		serverOpts = append(serverOpts, grpc.Creds(credentials.NewTLS(tlsConfig)))

		// Configure support for checking revoked certificates
		s.config.crlValidator.SyncLoop(context.TODO())
		s.config.crlValidator.Configure(tlsConfig, s.config.maxCRLValidityDays)
	} else {
		log.Logger().Info("TLS is disabled, make sure the Nuts Node is behind a TLS terminator which performs TLS authentication.")
	}

	// Create gRPC server for inbound connectionList and associate it with the protocols
	s.grpcServer = grpc.NewServer(serverOpts...)
	for _, prot := range s.protocols {
		grpcProtocol, ok := prot.(InboundStreamer)
		if ok {
			grpcProtocol.RegisterService(s, s.handleInboundStream)
		}
	}

	// Start serving from the gRPC server
	go func(server *grpc.Server, listener net.Listener) {
		err := server.Serve(listener)
		if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			log.Logger().Errorf("gRPC server errored: %v", err)
			s.Stop()
		}
	}(s.grpcServer, s.listener)

	log.Logger().Infof("gRPC server started on %s", s.config.listenAddress)
	return nil
}

func (s grpcConnectionManager) Stop() {
	log.Logger().Info("Stopping gRPC connection manager")
	s.connections.closeAll()

	s.grpcServerMutex.Lock()
	defer s.grpcServerMutex.Unlock()

	// Stop gRPC server
	if s.grpcServer != nil {
		s.grpcServer.GracefulStop()
		s.grpcServer = nil
		s.listener = nil // TCP listener is stopped by calling grpcServer.Stop()
	}
}

func (s grpcConnectionManager) Connect(peerAddress string) {
	connection, isNew := s.connections.getOrRegister(transport.Peer{Address: peerAddress}, s.dialer)
	if !isNew {
		log.Logger().Infof("A connection for %s already exists.", peerAddress)
		return
	}

	var tlsConfig *tls.Config
	if s.config.tlsEnabled() {
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{
				s.config.clientCert,
			},
			RootCAs: s.config.trustStore,
		}
	}

	connection.open(tlsConfig, func(grpcConn *grpc.ClientConn) {
		// Callback must block until streams or the connection is closed, then the connector will reconnect.
		err := s.openOutboundStreams(connection, grpcConn)
		if err != nil {
			log.Logger().Errorf("Error while setting up outbound gRPC streams, disconnecting (peer=%s): %v", connection.getPeer(), err)
			connection.close()
		}
	})
}

func (s grpcConnectionManager) Peers() []transport.Peer {
	return s.connections.listConnected()
}

// RegisterService implements grpc.ServiceRegistrar to register the gRPC services protocols expose.
func (s grpcConnectionManager) RegisterService(desc *grpc.ServiceDesc, impl interface{}) {
	s.grpcServer.RegisterService(desc, impl)
}

// openOutboundStreams instructs the protocols that support gRPC streaming to open their streams.
// The resulting grpc.ClientStream(s) must be registered on the managedConnection.
// If an error is returned the connection should be closed.
func (s *grpcConnectionManager) openOutboundStreams(connection managedConnection, grpcConn *grpc.ClientConn) error {
	protocolNum := 0
	// Call gRPC-enabled protocols, block until they close
	for _, prot := range s.protocols {
		grpcProtocol, ok := prot.(OutboundStreamer)
		if !ok {
			// Not a gRPC streaming protocol
			continue
		}
		streamContext, err := s.openOutboundStream(connection, grpcConn, grpcProtocol)
		if err != nil {
			log.Logger().Warnf("%T: Failed to open gRPC stream (addr=%s): %v", prot, grpcConn.Target(), err)
			continue
		}

		go func() {
			// Waits for the clientStream to be done (other side closed the stream), then we close the connection on our side
			<-streamContext.Done()
			connection.close()
		}()

		protocolNum++
	}
	if protocolNum == 0 {
		return fmt.Errorf("could not use any of the supported protocols to communicate with peer (id=%s)", connection.getPeer())
	}
	<-connection.closer() // block until connection is closed
	return nil
}

func (s *grpcConnectionManager) openOutboundStream(connection managedConnection, grpcConn *grpc.ClientConn, grpcProtocol OutboundStreamer) (context.Context, error) {
	outgoingContext := metadata.NewOutgoingContext(context.Background(), constructMetadata(s.config.peerID))
	streamContext, err := grpcProtocol.OpenStream(outgoingContext, grpcConn, func(clientStream grpc.ClientStream) (transport.Peer, error) {
		// Read peer ID from metadata
		peerHeaders, err := clientStream.Header()
		if err != nil {
			return transport.Peer{}, fmt.Errorf("failed to read gRPC headers: %w", err)
		}
		if len(peerHeaders) == 0 {
			return transport.Peer{}, fmt.Errorf("peer didn't send any headers, maybe the protocol version is not supported")
		}
		peerID, err := readMetadata(peerHeaders)
		if err != nil {
			return transport.Peer{}, fmt.Errorf("failed to read peer ID header: %w", err)
		}

		// Check whether we're already connected
		if s.connections.connected(transport.Peer{ID: peerID}) {
			// This can happen when the peer connected to us previously, and now we connect back to them.
			// TODO: Although nothing breaks, this spams the log of this node with warnings and errors because,
			//       the outbound connector just keeps connecting. There are 2 solutions to this:
			//       1. Merge the connection that was created to make the outbound connection with the existing inbound connection (complicated)
			//       2. Return the resolved peer ID to the outbound connector, which in turn checks whether its already connected to that peer (more dependency hell).
			log.Logger().Warnf("We connected to a peer that we're already connected to (peer=%s)", peerID)
			return transport.Peer{}, ErrAlreadyConnected
		}

		if !connection.verifyOrSetPeerID(peerID) {
			return transport.Peer{}, fmt.Errorf("peer sent invalid ID (id=%s)", peerID)
		}

		connection.registerClientStream(clientStream)

		return transport.Peer{
			ID:      peerID,
			Address: grpcConn.Target(),
		}, nil
	}, connection.closer())
	return streamContext, err
}

func (s *grpcConnectionManager) handleInboundStream(inboundStream grpc.ServerStream) (transport.Peer, <-chan struct{}, error) {
	peerCtx, _ := grpcPeer.FromContext(inboundStream.Context())
	log.Logger().Tracef("New peer connected from %s", peerCtx.Addr)

	// Send our Peer ID
	if err := inboundStream.SendHeader(constructMetadata(s.config.peerID)); err != nil {
		log.Logger().Errorf("Unable to accept gRPC stream (remote address: %s), unable to send headers: %v", peerCtx.Addr, err)
		return transport.Peer{}, nil, errors.New("unable to send headers")
	}

	// Build peer info and check it
	md, ok := metadata.FromIncomingContext(inboundStream.Context())
	if !ok {
		return transport.Peer{}, nil, errors.New("unable to read metadata")
	}
	peerID, err := readMetadata(md)
	if err != nil {
		return transport.Peer{}, nil, errors.New("unable to read peer ID")
	}
	peer := transport.Peer{
		ID:      peerID,
		Address: peerCtx.Addr.String(),
	}
	// TODO: Need to authenticate PeerID, to make sure a second stream with a known PeerID is from the same node (maybe even connection).
	//       Use address from peer context?

	// TODO: what if we had an outbound outboundConnector which couldn't connect, and now the peer connects inbound?
	if s.connections.connected(transport.Peer{ID: peerID}) {
		return peer, nil, ErrAlreadyConnected
	}

	log.Logger().Infof("New peer connected (peer=%s)", peer)

	connection, _ := s.connections.getOrRegister(peer, s.dialer)
	connection.registerServerStream(inboundStream)
	return peer, connection.closer(), nil
}
