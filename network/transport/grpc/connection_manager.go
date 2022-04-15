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
	"errors"
	"fmt"
	"go.etcd.io/bbolt"
	"net"
	"sync"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/network/transport"
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
	if !is {
		return errors.Is(s.error, other)
	}
	return is
}

// NewGRPCConnectionManager creates a new ConnectionManager that accepts/creates connections which communicate using the given protocols.
func NewGRPCConnectionManager(config Config, grpcDB *bbolt.DB, nodeDIDResolver transport.NodeDIDResolver, authenticator Authenticator, protocols ...transport.Protocol) transport.ConnectionManager {
	var grpcProtocols []Protocol
	for _, curr := range protocols {
		// For now, only gRPC protocols are supported
		protocol, ok := curr.(Protocol)
		if ok {
			grpcProtocols = append(grpcProtocols, protocol)
		}
	}
	cm := &grpcConnectionManager{
		protocols:       grpcProtocols,
		nodeDIDResolver: nodeDIDResolver,
		authenticator:   authenticator,
		config:          config,
		connections:     &connectionList{},
		grpcServerMutex: &sync.Mutex{},
		listenerCreator: config.listener,
		dialer:          config.dialer,
		db:              grpcDB,
	}
	cm.ctx, cm.ctxCancel = context.WithCancel(context.Background())
	return cm
}

// grpcConnectionManager is a ConnectionManager that does not discover peers on its own, but just connects to the peers for which Connect() is called.
type grpcConnectionManager struct {
	protocols        []Protocol
	config           Config
	connections      *connectionList
	grpcServer       *grpc.Server
	grpcServerMutex  *sync.Mutex
	ctx              context.Context
	ctxCancel        func()
	listener         net.Listener
	listenerCreator  func(string) (net.Listener, error)
	dialer           dialer
	authenticator    Authenticator
	nodeDIDResolver  transport.NodeDIDResolver
	stopCRLValidator func()
	observers        []transport.StreamStateObserverFunc
	db               *bbolt.DB
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
	log.Logger().Debug("Stopping gRPC connection manager")
	s.connections.forEach(func(connection Connection) {
		connection.stopConnecting()
		connection.disconnect()
	})

	if s.ctxCancel != nil {
		s.ctxCancel()
	}

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

func (s grpcConnectionManager) Connect(peerAddress string, options ...transport.ConnectionOption) {
	peer := transport.Peer{Address: peerAddress}
	for _, o := range options {
		o(&peer)
	}
	connection, isNew := s.connections.getOrRegister(s.ctx, peer, s.dialer)
	if !isNew {
		log.Logger().Infof("A connection for %s already exists.", peer.Address)
		return
	}
	s.startTracking(peer.Address, connection)
}

func (s *grpcConnectionManager) RegisterObserver(observer transport.StreamStateObserverFunc) {
	s.observers = append(s.observers, observer)
}

func (s *grpcConnectionManager) notifyObservers(peer transport.Peer, protocol transport.Protocol, state transport.StreamState) {
	log.Logger().Debugf("Observed stream state change (peer=%s, protocol=V%d, state=%s)", peer.ID, protocol.Version(), state)
	for _, observer := range s.observers {
		observer(peer, state, protocol)
	}
}

func (s grpcConnectionManager) Peers() []transport.Peer {
	var peers []transport.Peer
	for _, curr := range s.connections.All() {
		if curr.IsConnected() {
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
		s.notifyObservers(connection.Peer(), protocol, transport.StateConnected)

		go func() {
			// Waits for the clientStream to be done (other side closed the stream), then we disconnect the connection on our side
			<-clientStream.Context().Done()
			s.notifyObservers(connection.Peer(), protocol, transport.StateDisconnected)
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

func (s *grpcConnectionManager) openOutboundStream(connection Connection, protocol Protocol, grpcConn grpc.ClientConnInterface, md metadata.MD) (grpc.ClientStream, error) {
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

	// When 2 nodes connect to each other, the connections will have to be deduplicated.
	// When a node receives an inbound connection from a peer which it is already connected to, it must disconnect that new connection.
	// This means the connecting side (outbound) should stop connecting to that address, because it's already connected.
	// But it can't just clean up the outbound connection,
	// since it's a discovered Nuts Node address which is not known by the existing inbound connection.
	// To avoid "losing" that address it should start the outbound connector on the inbound connection,
	// so that it can make an outbound connection when the inbound connection is closed.
	existingConnection := s.connections.Get(ByPeerID(peerID))
	if existingConnection != nil && existingConnection != connection {
		connection.stopConnecting()
		s.connections.remove(connection)
		s.startTracking(connection.Peer().Address, existingConnection)
		return nil, fatalError{error: ErrAlreadyConnected}
	}

	if !connection.verifyOrSetPeerID(peerID) {
		return nil, fatalError{error: fmt.Errorf("peer sent invalid ID (id=%s)", peerID)}
	}

	// When bootstrap node, this instance has the AcceptUnauthenticated param
	peer := connection.Peer()
	peerFromCtx, _ := grpcPeer.FromContext(clientStream.Context())

	authenticatedPeer, err := s.authenticate(nodeDID, peer, peerFromCtx)
	if err != nil {
		return nil, fatalError{error: err}
	}

	connection.setPeer(authenticatedPeer)

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
		log.Logger().Debugf("Peer sent invalid peer ID, headers: %v", md)
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
	connection, _ := s.connections.getOrRegister(s.ctx, peer, s.dialer)
	if !connection.registerStream(protocol, inboundStream) {
		return ErrAlreadyConnected
	}

	s.notifyObservers(peer, protocol, transport.StateConnected)
	connection.waitUntilDisconnected()
	s.notifyObservers(peer, protocol, transport.StateDisconnected)

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

// startTracking starts the outbound connector on the given connection, meaning it starts to connect to the given address.
// If it is already connected, it will try to reconnect when disconnected.
func (s *grpcConnectionManager) startTracking(address string, connection Connection) {
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

	backoff := NewPersistedBackoff(s.db, address, defaultBackoff())
	connection.startConnecting(address, backoff, tlsConfig, func(grpcConn *grpc.ClientConn) bool {
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
