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
	"net"
	"sync"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	grpcPeer "google.golang.org/grpc/peer"
)

const defaultMaxMessageSizeInBytes = 1024 * 512

const protocolVersionV1 = "v1"          // required for backwards compatibility with v1
const protocolVersionHeader = "version" // required for backwards compatibility with v1
const peerIDHeader = "peerID"
const nodeDIDHeader = "nodeDID"

// ErrNodeDIDAuthFailed is the error message returned to the peer when the node DID it sent could not be authenticated.
// It is specified by RFC017.
var ErrNodeDIDAuthFailed = errors.New("nodeDID authentication failed")

// ErrAlreadyConnected indicates the node is already connected to the peer.
var ErrAlreadyConnected = errors.New("already connected")

// MaxMessageSizeInBytes defines the maximum size of an in- or outbound gRPC/Protobuf message
var MaxMessageSizeInBytes = defaultMaxMessageSizeInBytes

type fatalError struct {
	error
}

func (s fatalError) Error() string {
	return s.error.Error()
}

func (s fatalError) Is(other error) bool {
	_, is := other.(fatalError)
	return is
}

// NewGRPCConnectionManager creates a new ConnectionManager that accepts/creates connections which communicate using the given protocols.
func NewGRPCConnectionManager(config Config, nodeDIDResolver transport.NodeDIDResolver, authenticator Authenticator, protocols ...transport.Protocol) transport.ConnectionManager {
	var grpcProtocols []Protocol
	for _, curr := range protocols {
		// For now, only gRPC protocols are supported
		protocol := curr.(Protocol)
		grpcProtocols = append(grpcProtocols, protocol)
	}
	return &grpcConnectionManager{
		protocols:       grpcProtocols,
		nodeDIDResolver: nodeDIDResolver,
		authenticator:   authenticator,
		config:          config,
		connections:     &connectionList{},
		grpcServerMutex: &sync.Mutex{},
		listenerCreator: config.listener,
		dialer:          config.dialer,
	}
}

// grpcConnectionManager is a ConnectionManager that does not discover peers on its own, but just connects to the peers for which Connect() is called.
type grpcConnectionManager struct {
	protocols        []Protocol
	config           Config
	connections      *connectionList
	grpcServer       *grpc.Server
	grpcServerMutex  *sync.Mutex
	listener         net.Listener
	listenerCreator  func(string) (net.Listener, error)
	dialer           dialer
	authenticator    Authenticator
	nodeDIDResolver  transport.NodeDIDResolver
	stopCRLValidator func()
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
			MinVersion:   core.MinTLSVersion,
		}
		serverOpts = append(serverOpts, grpc.Creds(credentials.NewTLS(tlsConfig)))

		// Configure support for checking revoked certificates
		var crlValidatorCtx context.Context
		crlValidatorCtx, s.stopCRLValidator = context.WithCancel(context.Background())
		s.config.crlValidator.SyncLoop(crlValidatorCtx)
		s.config.crlValidator.Configure(tlsConfig, s.config.maxCRLValidityDays)
	} else {
		log.Logger().Info("TLS is disabled, make sure the Nuts Node is behind a TLS terminator which performs TLS authentication.")
	}

	// Create gRPC server for inbound connectionList and associate it with the protocols
	s.grpcServer = grpc.NewServer(serverOpts...)
	for _, prot := range s.protocols {
		func(protocol Protocol) {
			prot.Register(s, func(stream grpc.ServerStream) error {
				return s.handleInboundStream(protocol, stream)
			}, s.connections, s)
		}(prot)
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

func (s *grpcConnectionManager) Stop() {
	log.Logger().Info("Stopping gRPC connection manager")
	s.connections.forEach(func(connection Connection) {
		connection.stopConnecting()
		connection.disconnect()
	})

	s.grpcServerMutex.Lock()
	defer s.grpcServerMutex.Unlock()

	// Stop gRPC server
	if s.grpcServer != nil {
		s.grpcServer.GracefulStop()
		s.grpcServer = nil
		s.listener = nil // TCP listener is stopped by calling grpcServer.Stop()
	}

	if s.stopCRLValidator != nil {
		s.stopCRLValidator()
	}
}

func (s grpcConnectionManager) Connect(peerAddress string, acceptUnauthenticated bool) {
	connection, isNew := s.connections.getOrRegister(transport.Peer{Address: peerAddress, AcceptUnauthenticated: acceptUnauthenticated}, s.dialer)
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
			RootCAs:    s.config.trustStore,
			MinVersion: core.MinTLSVersion,
		}
	}

	connection.startConnecting(tlsConfig, func(grpcConn *grpc.ClientConn) bool {
		err := s.openOutboundStreams(connection, grpcConn)
		if err != nil {
			log.Logger().Errorf("Error while setting up outbound gRPC streams, disconnecting (peer=%s): %v", connection.Peer(), err)
			connection.disconnect()
			_ = grpcConn.Close()
			return false
		}
		return true
	})
}

func (s grpcConnectionManager) Peers() []transport.Peer {
	var peers []transport.Peer
	for _, curr := range s.connections.All() {
		if curr.Connected() {
			peers = append(peers, curr.Peer())
		}
	}
	return peers
}

func (s *grpcConnectionManager) Diagnostics() []core.DiagnosticResult {
	return append([]core.DiagnosticResult{ownPeerIDStatistic{s.config.peerID}}, s.connections.Diagnostics()...)
}

// RegisterService implements grpc.ServiceRegistrar to register the gRPC services protocols expose.
func (s grpcConnectionManager) RegisterService(desc *grpc.ServiceDesc, impl interface{}) {
	s.grpcServer.RegisterService(desc, impl)
}

// openOutboundStreams instructs the protocols that support gRPC streaming to open their streams.
// The resulting grpc.ClientStream(s) must be registered on the Connection.
// If an error is returned the connection should be closed.
func (s *grpcConnectionManager) openOutboundStreams(connection Connection, grpcConn *grpc.ClientConn) error {
	md, err := s.constructMetadata()
	if err != nil {
		return err
	}

	protocolNum := 0
	// Call gRPC-enabled protocols, block until they close
	for _, prot := range s.protocols {
		protocol, ok := prot.(Protocol)
		if !ok {
			// Not a gRPC streaming protocol
			continue
		}

		clientStream, err := s.openOutboundStream(connection, protocol, grpcConn, md)
		if err != nil {
			log.Logger().Warnf("%T: Failed to open gRPC stream (addr=%s): %v", protocol, grpcConn.Target(), err)
			if errors.Is(err, fatalError{}) {
				// Error indicates connection should be closed.
				return err
			}
			// Non-fatal error: other protocols may continue
			continue
		}
		log.Logger().Debugf("%T: Opened gRPC stream (peer=%s)", prot, connection.Peer())

		go func() {
			// Waits for the clientStream to be done (other side closed the stream), then we disconnect the connection on our side
			<-clientStream.Context().Done()
			connection.disconnect()
		}()

		protocolNum++
	}
	if protocolNum == 0 {
		return fmt.Errorf("could not use any of the supported protocols to communicate with peer (id=%s)", connection.Peer())
	}
	// Function must block until streams are closed or disconnect() is called.
	connection.waitUntilDisconnected()
	_ = grpcConn.Close()
	return nil
}

func (s *grpcConnectionManager) openOutboundStream(connection Connection, protocol Protocol, grpcConn *grpc.ClientConn, md metadata.MD) (grpc.ClientStream, error) {
	outgoingContext := metadata.NewOutgoingContext(context.Background(), md)
	clientStream, err := protocol.CreateClientStream(outgoingContext, grpcConn)
	if err != nil {
		return nil, fatalError{error: err}
	}

	// Read peer ID from metadata
	peerHeaders, err := clientStream.Header()
	if err != nil {
		return nil, fatalError{error: fmt.Errorf("failed to read gRPC headers: %w", err)}
	}
	if len(peerHeaders) == 0 {
		return nil, fmt.Errorf("peer didn't send any headers, maybe the protocol version is not supported")
	}
	peerID, nodeDID, err := readMetadata(peerHeaders)
	if err != nil {
		return nil, fatalError{error: fmt.Errorf("failed to read peer ID header: %w", err)}
	}

	if !connection.verifyOrSetPeerID(peerID) {
		return nil, fatalError{error: fmt.Errorf("peer sent invalid ID (id=%s)", peerID)}
	}

	//when bootstrap node, this instance has the AcceptUnauthenticated param
	peer := connection.Peer()
	peerFromCtx, _ := grpcPeer.FromContext(clientStream.Context())
	peer, err = s.authenticate(nodeDID, peer, peerFromCtx)
	if err != nil {
		return nil, fatalError{error: err}
	}

	if !connection.registerStream(protocol, clientStream) {
		// This can happen when the peer connected to us previously, and now we connect back to them.
		log.Logger().Warnf("We connected to a peer that we're already connected to (peer=%s)", peerID)
		return nil, fatalError{error: ErrAlreadyConnected}
	}

	return clientStream, nil
}

func (s *grpcConnectionManager) authenticate(nodeDID did.DID, peer transport.Peer, peerFromCtx *grpcPeer.Peer) (transport.Peer, error) {
	if !nodeDID.Empty() {
		authenticatedPeer, err := s.authenticator.Authenticate(nodeDID, *peerFromCtx, peer)
		if err != nil {
			// Error message below is spec'd by RFC017
			log.Logger().Warnf("Peer node DID could not be authenticated (did=%s): %v", nodeDID, err)
			return transport.Peer{}, ErrNodeDIDAuthFailed
		}
		return authenticatedPeer, nil
	}
	return peer, nil
}

func (s *grpcConnectionManager) handleInboundStream(protocol Protocol, inboundStream grpc.ServerStream) error {
	peerFromCtx, _ := grpcPeer.FromContext(inboundStream.Context())
	log.Logger().Tracef("New peer connected from %s", peerFromCtx.Addr)

	// Send our headers
	md, err := s.constructMetadata()
	if err != nil {
		return err
	}
	if err := inboundStream.SendHeader(md); err != nil {
		log.Logger().Errorf("Unable to accept gRPC stream (remote address: %s), unable to send headers: %v", peerFromCtx.Addr, err)
		return errors.New("unable to send headers")
	}

	// Build peer info and check it
	md, ok := metadata.FromIncomingContext(inboundStream.Context())
	if !ok {
		return errors.New("unable to read metadata")
	}
	peerID, nodeDID, err := readMetadata(md)
	if err != nil {
		return errors.New("unable to read peer ID")
	}
	peer := transport.Peer{
		ID:      peerID,
		Address: peerFromCtx.Addr.String(),
	}
	log.Logger().Debugf("New inbound stream from peer (peer=%s,protocol=%T)", peer, inboundStream)
	peer, err = s.authenticate(nodeDID, peer, peerFromCtx)
	if err != nil {
		return err
	}

	// TODO: Need to authenticate PeerID, to make sure a second stream with a known PeerID is from the same node (maybe even connection).
	//       Use address from peer context?
	connection, _ := s.connections.getOrRegister(peer, s.dialer)
	if !connection.registerStream(protocol, inboundStream) {
		return ErrAlreadyConnected
	}
	connection.waitUntilDisconnected()
	s.connections.remove(connection)
	return nil
}

func (s *grpcConnectionManager) constructMetadata() (metadata.MD, error) {
	md := metadata.New(map[string]string{
		peerIDHeader:          string(s.config.peerID),
		protocolVersionHeader: protocolVersionV1, // required for backwards compatibility with v1
	})

	nodeDID, err := s.nodeDIDResolver.Resolve()
	if err != nil {
		return nil, fmt.Errorf("error reading local node DID: %w", err)
	}
	if !nodeDID.Empty() {
		md.Set(nodeDIDHeader, nodeDID.String())
	}
	return md, nil
}
