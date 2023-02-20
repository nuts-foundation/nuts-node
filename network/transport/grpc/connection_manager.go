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
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	grpcPeer "google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"net"
	"time"
)

const defaultMaxMessageSizeInBytes = 1024 * 512

var grpcGoroutineShutdownTimeout = 10 * time.Second

const peerIDHeader = "peerID"
const nodeDIDHeader = "nodeDID"

// ErrNodeDIDAuthFailed is the error message returned to the peer when the node DID it sent could not be authenticated.
// It is specified by RFC017.
var ErrNodeDIDAuthFailed = status.Error(codes.Unauthenticated, "nodeDID authentication failed")

// ErrAlreadyConnected indicates the node is already connected to the peer.
var ErrAlreadyConnected = errors.New("already connected")

// MaxMessageSizeInBytes defines the maximum size of an in- or outbound gRPC/Protobuf message
var MaxMessageSizeInBytes = defaultMaxMessageSizeInBytes

// defaultInterceptors aids testing
var defaultInterceptors []grpc.StreamServerInterceptor

type fatalError struct {
	error
}

func (s fatalError) Error() string {
	return s.error.Error()
}

func (s fatalError) Unwrap() error {
	return s.error
}

// NewGRPCConnectionManager creates a new ConnectionManager that accepts/creates connections which communicate using the given protocols.
func NewGRPCConnectionManager(config Config, connectionStore stoabs.KVStore, nodeDIDResolver transport.NodeDIDResolver, authenticator Authenticator, protocols ...transport.Protocol) transport.ConnectionManager {
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
		dialer:          config.dialer,
		connectionStore: connectionStore,
	}
	cm.registerPrometheusMetrics()
	cm.ctx, cm.ctxCancel = context.WithCancel(context.Background())
	return cm
}

// grpcConnectionManager is a ConnectionManager that does not discover peers on its own, but just connects to the peers for which Connect() is called.
type grpcConnectionManager struct {
	protocols           []Protocol
	config              Config
	connections         *connectionList
	grpcServer          *grpc.Server
	ctx                 context.Context
	ctxCancel           func()
	listener            net.Listener
	dialer              dialer
	authenticator       Authenticator
	nodeDIDResolver     transport.NodeDIDResolver
	observers           []transport.StreamStateObserverFunc
	connectionStore     stoabs.KVStore
	peersCounter        prometheus.Gauge
	recvMessagesCounter *prometheus.CounterVec
	sentMessagesCounter *prometheus.CounterVec
}

// newGrpcServer configures a new grpc.Server. context.Context is used to cancel the crlValidator
func newGrpcServer(ctx context.Context, config Config) (*grpc.Server, error) {
	serverOpts := []grpc.ServerOption{
		grpc.MaxRecvMsgSize(MaxMessageSizeInBytes),
		grpc.MaxSendMsgSize(MaxMessageSizeInBytes),
	}

	var serverInterceptors []grpc.StreamServerInterceptor
	serverInterceptors = append(serverInterceptors, defaultInterceptors...)

	// Configure TLS if enabled
	if config.tlsEnabled() {
		// Some form of TLS is enabled
		if config.serverCert != nil {
			// TLS is terminated at the Nuts node (no offloading)
			tlsConfig := &tls.Config{
				Certificates: []tls.Certificate{*config.serverCert},
				ClientAuth:   tls.RequireAndVerifyClientCert,
				ClientCAs:    config.trustStore,
				MinVersion:   core.MinTLSVersion,
			}
			serverOpts = append(serverOpts, grpc.Creds(credentials.NewTLS(tlsConfig)))

			// Configure support for checking revoked certificates
			config.crlValidator.SyncLoop(ctx)
			config.crlValidator.Configure(tlsConfig, config.maxCRLValidityDays)
		} else {
			// TLS offloading for incoming traffic
			if config.clientCertHeaderName == "" {
				// Invalid config
				return nil, errors.New("tls.certheader must be configured to enable TLS offloading ")
			}
			serverInterceptors = append(serverInterceptors, newAuthenticationInterceptor(config.clientCertHeaderName))
		}
	} else {
		log.Logger().Info("TLS is disabled, this is very unsecure and only suitable for demo/development environments.")
	}

	// Chain interceptors. ipInterceptor is added last, so it processes the stream first.
	serverInterceptors = append(serverInterceptors, ipInterceptor)
	serverOpts = append(serverOpts, grpc.ChainStreamInterceptor(serverInterceptors...))

	// Create gRPC server for inbound connectionList and associate it with the protocols
	return grpc.NewServer(serverOpts...), nil
}

func (s *grpcConnectionManager) Start() error {
	if s.config.listenAddress == "" {
		log.Logger().Info("Not starting gRPC server, connections will only be outbound.")
		return nil
	}
	log.Logger().Debugf("Starting gRPC server on %s", s.config.listenAddress)

	var err error
	s.listener, err = s.config.listener(s.config.listenAddress)
	if err != nil {
		return err
	}

	// Create gRPC server for inbound connectionList and associate it with the protocols
	s.grpcServer, err = newGrpcServer(s.ctx, s.config)
	if err != nil {
		return err
	}
	for _, protocol := range s.protocols {
		protocol.Register(s, func(stream grpc.ServerStream) error {
			return s.handleInboundStream(protocol, stream)
		}, s.connections, s)
	}

	// Start serving from the gRPC server
	go func(server *grpc.Server, listener net.Listener) {
		err := server.Serve(listener)
		if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			log.Logger().
				WithError(err).
				Error("gRPC server errored")
			s.Stop()
		}
	}(s.grpcServer, s.listener)

	log.Logger().Infof("gRPC server started on %s", s.config.listenAddress)
	return nil
}

func (s *grpcConnectionManager) Stop() {
	log.Logger().Debug("Stopping gRPC connection manager")
	// Signal crlValidator and active connections to stop
	s.ctxCancel()
	// Stop outbound connectors
	s.connections.forEach(func(connection Connection) {
		connection.stopConnecting()
		connection.disconnect()
	})
	// Everything should be stopped now
	if s.grpcServer != nil { // is nil when not accepting inbound connections
		s.grpcServer.GracefulStop() // also closes listener
	}

	prometheus.Unregister(s.peersCounter)
	prometheus.Unregister(s.sentMessagesCounter)
	prometheus.Unregister(s.recvMessagesCounter)
}

func (s *grpcConnectionManager) Connect(peerAddress string) {
	peer := transport.Peer{Address: peerAddress}
	connection, isNew := s.connections.getOrRegister(s.ctx, peer, s.dialer, true)
	if !isNew {
		log.Logger().
			WithField(core.LogFieldPeerAddr, peer.Address).
			Info("Connection for peer already exists.")
		return
	}
	s.startTracking(peer.Address, connection)
}

func (s *grpcConnectionManager) RegisterObserver(observer transport.StreamStateObserverFunc) {
	s.observers = append(s.observers, observer)
}

func (s *grpcConnectionManager) notifyObservers(peer transport.Peer, protocol transport.Protocol, state transport.StreamState) {
	log.Logger().
		WithFields(peer.ToFields()).
		WithField(core.LogFieldProtocolVersion, protocol.Version()).
		Debugf("Stream state changed to %s", state)
	for _, observer := range s.observers {
		observer(peer, state, protocol)
	}
}

func (s *grpcConnectionManager) Peers() []transport.Peer {
	var peers []transport.Peer

	for _, curr := range s.connections.AllMatching(ByConnected()) {
		peers = append(peers, curr.Peer())
	}
	return peers
}

func (s *grpcConnectionManager) Diagnostics() []core.DiagnosticResult {
	return append([]core.DiagnosticResult{ownPeerIDStatistic{s.config.peerID}}, s.connections.Diagnostics()...)
}

// RegisterService implements grpc.ServiceRegistrar to register the gRPC services protocols expose.
func (s *grpcConnectionManager) RegisterService(desc *grpc.ServiceDesc, impl interface{}) {
	s.grpcServer.RegisterService(desc, impl)
}

// openOutboundStreams instructs the protocols that support gRPC streaming to open their streams.
// The resulting grpc.ClientStream(s) must be registered on the Connection.
// If an error is returned the connection should be closed.
func (s *grpcConnectionManager) openOutboundStreams(connection Connection, grpcConn *grpc.ClientConn, backoff Backoff) error {
	md, err := s.constructMetadata()
	if err != nil {
		return err
	}

	protocolNum := 0
	// Call gRPC-enabled protocols, block until they close
	for _, protocol := range s.protocols {
		clientStream, err := s.openOutboundStream(connection, protocol, grpcConn, md)
		if err != nil {
			log.Logger().
				WithError(err).
				WithField(core.LogFieldPeerAddr, grpcConn.Target()).
				WithField(core.LogFieldProtocolVersion, protocol.Version()).
				Warn("Failed to open gRPC stream")
			if errors.As(err, new(fatalError)) {
				// Error indicates connection should be closed.
				return err
			}
			// Non-fatal error: other protocols may continue
			continue
		}
		peer := connection.Peer() // work with a copy of peer to avoid race condition due to disconnect() resetting it
		log.Logger().
			WithField(core.LogFieldProtocolVersion, protocol.Version()).
			WithFields(peer.ToFields()).
			Debug("Opened gRPC stream")
		s.notifyObservers(peer, protocol, transport.StateConnected)

		go func() {
			// Waits for the clientStream to be done (other side closed the stream), then we disconnect the connection on our side
			<-clientStream.Context().Done()
			s.notifyObservers(peer, protocol, transport.StateDisconnected)
			connection.disconnect()
		}()

		protocolNum++
	}
	if protocolNum == 0 {
		return fmt.Errorf("could not use any of the supported protocols to communicate with peer (id=%s)", connection.Peer())
	}

	s.peersCounter.Inc()
	defer s.peersCounter.Dec()

	// Function must block until streams are closed or disconnect() is called.
	connection.waitUntilDisconnected()
	_ = grpcConn.Close()

	if st := connection.CloseError(); st != nil && st.Code() == codes.Unauthenticated {
		// other side said unauthenticated, increase backoff
		backoff.Backoff()
		// return error so entire connection will be tried anew. Otherwise, backoff isn't honored
		return st.Err()
	}

	// Connection is OK, reset backoff it can immediately try reconnecting when it disconnects
	backoff.Reset(0)

	return nil
}

func (s *grpcConnectionManager) openOutboundStream(connection Connection, protocol Protocol, grpcConn grpc.ClientConnInterface, md metadata.MD) (grpc.ClientStream, error) {
	outgoingContext := metadata.NewOutgoingContext(s.ctx, md)
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

	authenticatedPeer := s.authenticate(nodeDID, peer, peerFromCtx)
	connection.setPeer(authenticatedPeer)

	wrappedStream := s.wrapStream(clientStream, protocol)
	if !connection.registerStream(protocol, wrappedStream) {
		// This can happen when the peer connected to us previously, and now we connect back to them.
		log.Logger().
			WithFields(peer.ToFields()).
			Warn("We connected to a peer that we're already connected to")
		return nil, fatalError{error: ErrAlreadyConnected}
	}

	return clientStream, nil
}

func (s *grpcConnectionManager) authenticate(nodeDID did.DID, peer transport.Peer, peerFromCtx *grpcPeer.Peer) transport.Peer {
	if !nodeDID.Empty() {
		var err error
		peer, err = s.authenticator.Authenticate(nodeDID, *peerFromCtx, peer)
		if err != nil {
			log.Logger().
				WithError(err).
				WithFields(peer.ToFields()).
				WithField(core.LogFieldDID, nodeDID).
				Warn("Peer node DID could not be authenticated")
			// Error message is spec'd by RFC017, because it is returned to the peer
			//return transport.Peer{}, ErrNodeDIDAuthFailed // TODO: removing this requires a spec change
		}
	}
	return peer
}

func (s *grpcConnectionManager) handleInboundStream(protocol Protocol, inboundStream grpc.ServerStream) error {
	peerFromCtx, _ := grpcPeer.FromContext(inboundStream.Context())
	log.Logger().
		WithField(core.LogFieldPeerAddr, peerFromCtx.Addr.String()).
		Trace("New peer connected")

	// Send our headers
	md, err := s.constructMetadata()
	if err != nil {
		return err
	}
	if err := inboundStream.SendHeader(md); err != nil {
		log.Logger().
			WithError(err).
			WithField(core.LogFieldPeerAddr, peerFromCtx.Addr.String()).
			Error("Unable to accept gRPC stream, unable to send headers")
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
	log.Logger().
		WithFields(peer.ToFields()).
		WithField(core.LogFieldProtocolVersion, protocol.Version()).
		Debug("New inbound stream from peer")
	peer = s.authenticate(nodeDID, peer, peerFromCtx)

	// TODO: Need to authenticate PeerID, to make sure a second stream with a known PeerID is from the same node (maybe even connection).
	//       Use address from peer context?
	connection, created := s.connections.getOrRegister(s.ctx, peer, s.dialer, false)
	if created {
		// If created is false, it's a second (or third...) protocol on the same connection
		s.peersCounter.Inc()
		defer s.peersCounter.Dec()
	}
	wrappedStream := s.wrapStream(inboundStream, protocol)
	if !connection.registerStream(protocol, wrappedStream) {
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
		peerIDHeader: string(s.config.peerID),
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
				*s.config.clientCert,
			},
			RootCAs:    s.config.trustStore,
			MinVersion: core.MinTLSVersion,
		}
	}

	backoff := NewPersistedBackoff(s.connectionStore, address, s.config.backoffCreator())
	cfg := connectorConfig{
		address:           address,
		tls:               tlsConfig,
		connectionTimeout: s.config.connectionTimeout,
	}

	connection.startConnecting(cfg, backoff, func(grpcConn *grpc.ClientConn) bool {
		err := s.openOutboundStreams(connection, grpcConn, backoff)
		if err != nil {
			log.Logger().
				WithError(err).
				WithFields(connection.Peer().ToFields()).
				Error("Error while setting up outbound gRPC streams, disconnecting")
			connection.disconnect()
			_ = grpcConn.Close()
			return false
		}
		return true
	})
}

func (s *grpcConnectionManager) wrapStream(stream Stream, protocol Protocol) prometheusStreamWrapper {
	return prometheusStreamWrapper{
		stream:              stream,
		protocol:            protocol,
		recvMessagesCounter: s.recvMessagesCounter,
		sentMessagesCounter: s.sentMessagesCounter,
	}
}

func (s *grpcConnectionManager) registerPrometheusMetrics() {
	s.peersCounter = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "nuts",
		Subsystem: "network",
		Name:      "peers",
		Help:      "Number of connected gRPC peers.",
	})
	_ = prometheus.Register(s.peersCounter)
	s.sentMessagesCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "nuts",
		Subsystem: "network_grpc",
		Name:      "messages_sent",
		Help:      "Number of gRPC messages sent per protocol and message type.",
	}, []string{"protocol", "message_type"})
	_ = prometheus.Register(s.sentMessagesCounter)
	s.recvMessagesCounter = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "nuts",
		Subsystem: "network_grpc",
		Name:      "messages_received",
		Help:      "Number of gRPC messages received per protocol and message type.",
	}, []string{"protocol", "message_type"})
	_ = prometheus.Register(s.recvMessagesCounter)
}
