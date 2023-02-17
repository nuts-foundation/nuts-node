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
	"net"
	"time"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	grpcPeer "google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

const defaultMaxMessageSizeInBytes = 1024 * 512

const peerIDHeader = "peerID"
const nodeDIDHeader = "nodeDID"

// ErrNodeDIDAuthFailed is the error message returned to the peer when the node DID it sent could not be authenticated.
// It is specified by RFC017.
var ErrNodeDIDAuthFailed = status.Error(codes.Unauthenticated, "nodeDID authentication failed")

// ErrUnexpectedNodeDID is the error used in outbound calling to signal that the peer sent a different NodeDID than expected.
// The DID has moved on, do not call it again until notified of its new address.
var ErrUnexpectedNodeDID = errors.New("this is not the node you are looking for")

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

type dialer func(ctx context.Context, target string, opts ...grpc.DialOption) (conn *grpc.ClientConn, err error)

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

	// client tls
	tlsDialOption := grpc.WithTransportCredentials(insecure.NewCredentials()) // No TLS, requires 'insecure' flag
	if config.tlsEnabled() {
		clientConfig := &tls.Config{
			Certificates: []tls.Certificate{
				*config.clientCert,
			},
			RootCAs:    config.trustStore,
			MinVersion: core.MinTLSVersion,
		}
		tlsDialOption = grpc.WithTransportCredentials(credentials.NewTLS(clientConfig)) // TLS authentication
	}

	cm := &grpcConnectionManager{
		protocols:         grpcProtocols,
		nodeDIDResolver:   nodeDIDResolver,
		authenticator:     authenticator,
		config:            config,
		addressBook:       newAddressBook(connectionStore, config.backoffCreator),
		connectionTimeout: config.connectionTimeout,
		connections:       &connectionList{},
		dialer:            config.dialer,
		dialOptions: []grpc.DialOption{
			grpc.WithBlock(),                 // Dial should block until connection succeeded (or time-out expired)
			grpc.WithReturnConnectionError(), // This option causes underlying errors to be returned when connections fail, rather than just "context deadline exceeded"
			grpc.WithDefaultCallOptions(
				grpc.MaxCallRecvMsgSize(MaxMessageSizeInBytes),
				grpc.MaxCallSendMsgSize(MaxMessageSizeInBytes),
			),
			grpc.WithUserAgent(core.UserAgent()),
			tlsDialOption,
		},
	}
	cm.registerPrometheusMetrics()
	cm.ctx, cm.ctxCancel = context.WithCancel(context.Background())

	return cm
}

// grpcConnectionManager is a ConnectionManager that does not discover peers on its own, but just connects to the peers for which Connect() is called.
type grpcConnectionManager struct {
	protocols           []Protocol
	config              Config
	grpcServer          *grpc.Server
	ctx                 context.Context
	ctxCancel           func()
	listener            net.Listener
	authenticator       Authenticator
	nodeDIDResolver     transport.NodeDIDResolver
	observers           []transport.StreamStateObserverFunc
	peersCounter        prometheus.Gauge
	recvMessagesCounter *prometheus.CounterVec
	sentMessagesCounter *prometheus.CounterVec

	addressBook *addressBook

	dialer
	dialOptions       []grpc.DialOption
	connectionTimeout time.Duration
	connections       *connectionList
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
			// TODO: CRL is started as part of inbound listening. Should this also start if inbound is disabled?
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
	// Start outbound
	go s.dialerLoop()

	// Start inbound
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
	s.ctxCancel() // stops dialerLoop and crlValidator
	s.connections.forEach(func(connection Connection) {
		connection.disconnect()
	})

	if s.grpcServer != nil { // is nil when not accepting inbound connections
		s.grpcServer.GracefulStop() // also closes listener
	}

	prometheus.Unregister(s.peersCounter)
	prometheus.Unregister(s.sentMessagesCounter)
	prometheus.Unregister(s.recvMessagesCounter)
}

func (s *grpcConnectionManager) dialerLoop() {
	log.Logger().Info("start dialing")
	var c *contact
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C: // TODO: what if the look takes longer than the ticker?
			for _, c = range s.addressBook.All() {
				select {
				case <-s.ctx.Done():
					// interrupt inner loop
					break
				default:
					// continue
				}

				// try to call
				switch {
				case s.hasActiveConnection(c.peer):
					continue
				case !c.backoff.Expired():
					continue
				case !c.dialing.CompareAndSwap(false, true):
					// this can occur when hasActiveConnection returns false due to the connection waiting for authentication
					continue
				default:
					// use the dialing lock acquired above to dial the getContact
					go func(cp *contact) {
						defer cp.dialing.Store(false) // reset call lock at the end of dialing
						s.dial(cp)
					}(c)
				}
			}
		}
	}
}

func (s *grpcConnectionManager) dial(contact *contact) {
	connection, isNew := s.connections.getOrRegister(s.ctx, contact.peer, true)
	if !isNew {
		// can only occur when receiving an inbound connection at the same time.
		log.Logger().WithFields(contact.peer.ToFields()).
			Debug("stop dialing, already has a connection")
		return
	}
	defer func() {
		// connection does not exist outside the dialer
		connection.disconnect()
		s.connections.remove(connection)
	}()

	// Open a grpc.ClientConn
	log.Logger().WithFields(contact.peer.ToFields()).Debug("connecting to peer")
	contact.attempts.Add(1)
	contact.lastAttempt.Store(time.Now())
	dialContext, cancel := context.WithTimeout(s.ctx, s.connectionTimeout)
	defer cancel()
	grpcClient, err := s.dialer(dialContext, contact.peer.Address, s.dialOptions...)
	if err != nil { // failed to connect
		log.Logger().WithError(err).WithFields(contact.peer.ToFields()).Debug("failed to open a grpc ClientConn")
		contact.backoff.Backoff()
		return
	}
	defer func() {
		if err := grpcClient.Close(); err != nil {
			log.Logger().WithError(err).WithFields(contact.peer.ToFields()).Debug("failed to close the grpc ClientConn")
		}
	}()
	log.Logger().WithFields(contact.peer.ToFields()).Debug("connected to peer (outbound)")

	// Connect protocol streams
	err = s.openOutboundStreams(connection, grpcClient) // blocking call, dial needs to be async
	if err != nil {
		// connection failed, increase backoff
		// TODO: check if this works as intended for multiple streams/protocols on the same connection
		contact.backoff.Backoff()
		if errors.Is(err, ErrUnexpectedNodeDID) {
			contact.backoff.Set(time.Hour * 24 * 365 * 100) // backoff expires after 100 years. Backoff must be reset when peer's (DID) address is updated.
		}
		log.Logger().WithError(err).WithFields(connection.Peer().ToFields()).
			Debug("Error while setting up outbound gRPC streams, disconnecting")
	} else {
		// Connection was OK, but now disconnected. Add a random wait to prevent simultaneous reconnecting.
		contact.backoff.Set(RandomBackoff(time.Second, 5*time.Second))
	}
}

func (s *grpcConnectionManager) hasActiveConnection(peer transport.Peer) bool {
	if peer.NodeDID.Empty() { // bootstrap matches on address + empty node DID
		return s.connections.Get(ByAddress(peer.Address), ByNodeDID(did.DID{})) != nil
	}
	// Only authenticated connections
	return s.connections.Get(ByNodeDID(peer.NodeDID), ByAuthenticated()) != nil
}

func (s *grpcConnectionManager) Connect(peerAddress string, peerDID did.DID) {
	peer := transport.Peer{Address: peerAddress, NodeDID: peerDID}
	if err := s.addressBook.Update(peer); err != nil {
		log.Logger().WithError(err).
			WithField(core.LogFieldPeerNodeDID, peer.NodeDID.String()).
			WithField(core.LogFieldPeerAddr, peer.Address).
			Info("failed to update address book with new peer details")
	}
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
	return append(append([]core.DiagnosticResult{ownPeerIDStatistic{s.config.peerID}}, s.connections.Diagnostics()...), s.addressBook.Diagnostics()...)
}

// RegisterService implements grpc.ServiceRegistrar to register the gRPC services protocols expose.
func (s *grpcConnectionManager) RegisterService(desc *grpc.ServiceDesc, impl interface{}) {
	s.grpcServer.RegisterService(desc, impl)
}

// openOutboundStreams instructs the protocols that support gRPC streaming to open their streams.
// The resulting grpc.ClientStream(s) must be registered on the Connection.
// If an error is returned the connection should be closed.
func (s *grpcConnectionManager) openOutboundStreams(connection Connection, grpcConn *grpc.ClientConn) error {
	md, err := s.constructMetadata(connection.Peer().NodeDID.Empty())
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

	if st := connection.CloseError(); st != nil && st.Code() == codes.Unauthenticated {
		// return error so entire connection will be tried anew. Otherwise, backoff isn't honored
		return st.Err()
	}

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
	if len(peerHeaders) == 0 { // non-fatal error
		return nil, fmt.Errorf("peer didn't send any headers, maybe the protocol version is not supported")
	}
	peerID, nodeDID, err := readMetadata(peerHeaders)
	if err != nil {
		return nil, fatalError{error: fmt.Errorf("failed to read peer ID header: %w", err)}
	}

	// Update connection information
	if !connection.verifyOrSetPeerID(peerID) {
		return nil, fatalError{error: fmt.Errorf("peer sent invalid ID (id=%s)", peerID)}
	}
	peerFromCtx, _ := grpcPeer.FromContext(clientStream.Context())
	expectedPeer := connection.Peer()
	connection.setPeer(expectedPeer)

	// Authenticate expected DID
	if !expectedPeer.NodeDID.Empty() { // do not authenticate bootstrap connections
		if nodeDID.Empty() {
			// Peer might be in maintenance mode, try again later
			return nil, fatalError{ErrNodeDIDAuthFailed}
		}
		if !expectedPeer.NodeDID.Equals(nodeDID) {
			// DID no longer lives at this address, don't call this DID again!
			return nil, fatalError{ErrUnexpectedNodeDID} // TODO: should this also wrap ErrNodeDIDAuthFailed?
		}
		// Call answered by the DID we are looking for. Try to authenticate.
		authenticatedPeer, err := s.authenticate(nodeDID, expectedPeer, peerFromCtx)
		if err != nil {
			return nil, fatalError{err}
		}
		connection.setPeer(authenticatedPeer)
	}

	wrappedStream := s.wrapStream(clientStream, protocol)
	if !connection.registerStream(protocol, wrappedStream) {
		// This can happen when the peer connected to us previously, and now we connect back to them.
		log.Logger().
			WithFields(connection.Peer().ToFields()).
			Warn("We connected to a peer that we're already connected to")
		return nil, fatalError{error: ErrAlreadyConnected}
	}

	return clientStream, nil
}

func (s *grpcConnectionManager) authenticate(nodeDID did.DID, peer transport.Peer, peerFromCtx *grpcPeer.Peer) (transport.Peer, error) {
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
			return transport.Peer{}, ErrNodeDIDAuthFailed
		}
	}
	return peer, nil
}

func (s *grpcConnectionManager) handleInboundStream(protocol Protocol, inboundStream grpc.ServerStream) error {
	peerFromCtx, _ := grpcPeer.FromContext(inboundStream.Context())
	log.Logger().
		WithField(core.LogFieldPeerAddr, peerFromCtx.Addr.String()).
		Trace("New peer connected")

	// Send our headers
	md, err := s.constructMetadata(false)
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
	peer, _ = s.authenticate(nodeDID, peer, peerFromCtx)

	// TODO: Need to authenticate PeerID, to make sure a second stream with a known PeerID is from the same node (maybe even connection).
	//       Use address from peer context?
	connection, created := s.connections.getOrRegister(s.ctx, peer, false)
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

func (s *grpcConnectionManager) constructMetadata(bootstrap bool) (metadata.MD, error) {
	md := metadata.New(map[string]string{})

	if bootstrap {
		// Older nodes (< v5.1) only match on peerID.
		// The postfix allows them to have a bootstrap connection and authenticated connection at the same time.
		md.Set(peerIDHeader, string(s.config.peerID)+"-bootstrap")
		return md, nil
	}

	md.Set(peerIDHeader, string(s.config.peerID))

	nodeDID, err := s.nodeDIDResolver.Resolve()
	if err != nil {
		return nil, fmt.Errorf("error reading local node DID: %w", err)
	}
	if !nodeDID.Empty() {
		md.Set(nodeDIDHeader, nodeDID.String())
	}
	return md, nil
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
