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

package p2p

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/network/transport"
	errors2 "github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	grpcPeer "google.golang.org/grpc/peer"
)

type dialer func(ctx context.Context, target string, opts ...grpc.DialOption) (conn *grpc.ClientConn, err error)

const connectingQueueChannelSize = 100
const eventChannelSize = 100
const messageBacklogChannelSize = 100
const maxMessageSizeInBytes = 1024 * 512

type grpcInterface struct {
	config InterfaceConfig

	grpcServer  *grpc.Server
	serverMutex *sync.Mutex
	listener    net.Listener

	// connectors contains the list of peers we're currently trying to connect to.
	connectors map[string]*connector
	// connectorAddChannel is used to communicate addresses of remote peers to connect to.
	connectorAddChannel chan string
	// Event channels which are listened to by, peers connects/disconnects
	peerConnectedChannel    chan Peer
	peerDisconnectedChannel chan Peer
	// conns is the list of active connections. Access MUST be wrapped in locking using connsMutex.
	conns map[PeerID]*connection
	// peersByAddr access MUST be wrapped in locking using connsMutex.
	peersByAddr      map[string]PeerID
	connsMutex       *sync.Mutex
	receivedMessages messageQueue
	grpcDialer       dialer
	configured       bool
}

func (n grpcInterface) EventChannels() (peerConnected chan Peer, peerDisconnected chan Peer) {
	return n.peerConnectedChannel, n.peerDisconnectedChannel
}

func (n grpcInterface) Configured() bool {
	return n.configured
}

func (n grpcInterface) Diagnostics() []core.DiagnosticResult {
	peers := n.Peers()
	return []core.DiagnosticResult{
		numberOfPeersStatistic{numberOfPeers: len(peers)},
		peersStatistic{peers: peers},
		ownPeerIDStatistic{peerID: n.config.PeerID},
	}
}

func (n *grpcInterface) Peers() []Peer {
	var result []Peer
	n.connsMutex.Lock()
	defer n.connsMutex.Unlock()
	for _, conn := range n.conns {
		result = append(result, conn.Peer)
	}
	return result
}

func (n *grpcInterface) Broadcast(message *transport.NetworkMessage) {
	n.connsMutex.Lock()
	defer n.connsMutex.Unlock()
	for _, conn := range n.conns {
		conn.outMessages <- message
	}
}

func (n grpcInterface) ReceivedMessages() MessageQueue {
	return n.receivedMessages
}

func (n grpcInterface) Send(peerID PeerID, message *transport.NetworkMessage) error {
	var conn *connection
	n.connsMutex.Lock()
	{
		defer n.connsMutex.Unlock()
		conn = n.conns[peerID]
	}
	if conn == nil {
		return fmt.Errorf("unknown peer: %s", peerID)
	}
	conn.outMessages <- message
	return nil
}

type connector struct {
	address string
	backoff Backoff
	dialer
}

func (c *connector) doConnect(ownID PeerID, tlsConfig *tls.Config) (*connection, error) {
	log.Logger().Debugf("Connecting to peer: %v", c.address)
	cxt := metadata.NewOutgoingContext(context.Background(), constructMetadata(ownID))
	dialContext, _ := context.WithTimeout(cxt, 5*time.Second)
	dialOptions := []grpc.DialOption{
		grpc.WithBlock(),                 // Dial should block until connection succeeded (or time-out expired)
		grpc.WithReturnConnectionError(), // This option causes underlying errors to be returned when connections fail, rather than just "context deadline exceeded"
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(maxMessageSizeInBytes),
			grpc.MaxCallSendMsgSize(maxMessageSizeInBytes),
		),
	}
	if tlsConfig != nil {
		dialOptions = append(dialOptions, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig))) // TLS authentication
	} else {
		dialOptions = append(dialOptions, grpc.WithInsecure()) // No TLS, requires 'insecure' flag
	}
	grpcConn, err := c.dialer(dialContext, c.address, dialOptions...)
	if err != nil {
		return nil, errors2.Wrap(err, "unable to connect")
	}
	client := transport.NewNetworkClient(grpcConn)
	messenger, err := client.Connect(cxt)
	if err != nil {
		log.Logger().Warnf("Failed to set up stream (addr=%s): %v", c.address, err)
		_ = grpcConn.Close()
		return nil, err
	}

	serverPeerID, err := c.readHeaders(messenger, grpcConn)
	if err != nil {
		log.Logger().Warnf("Error reading headers from server, closing connection (addr=%s): %v", c.address, err)
		_ = grpcConn.Close()
		return nil, err
	}
	conn := createConnection(Peer{
		ID:      serverPeerID,
		Address: c.address,
	}, messenger)
	conn.grpcConn = grpcConn

	log.Logger().Infof("Connected to peer (id=%s,addr=%s)", conn.ID, c.address)
	return conn, nil
}

func (c *connector) readHeaders(gate transport.Network_ConnectClient, grpcConn *grpc.ClientConn) (PeerID, error) {
	serverHeader, err := gate.Header()
	if err != nil {
		return "", err
	}
	serverPeerID, err := peerIDFromMetadata(serverHeader)
	if err != nil {
		return "", fmt.Errorf("unable to parse PeerID: %w", err)
	}
	if serverPeerID == "" {
		return "", errors.New("server didn't sent a PeerID")
	}
	return serverPeerID, nil
}

// NewInterface creates an interface to be used connect to peers in the network and exchange messages.
func NewInterface() Adapter {
	return &grpcInterface{
		conns:                   make(map[PeerID]*connection, 0),
		peersByAddr:             make(map[string]PeerID, 0),
		connectors:              make(map[string]*connector, 0),
		connectorAddChannel:     make(chan string, connectingQueueChannelSize),
		peerConnectedChannel:    make(chan Peer, eventChannelSize),
		peerDisconnectedChannel: make(chan Peer, eventChannelSize),
		connsMutex:              &sync.Mutex{},
		serverMutex:             &sync.Mutex{},
		receivedMessages:        messageQueue{c: make(chan PeerMessage, messageBacklogChannelSize)},
		grpcDialer:              grpc.DialContext,
	}
}

type messageQueue struct {
	c chan PeerMessage
}

func (m messageQueue) Get() PeerMessage {
	return <-m.c
}

func (n *grpcInterface) Configure(config InterfaceConfig) error {
	if config.PeerID == "" {
		return errors.New("PeerID is empty")
	}
	n.config = config
	n.configured = true
	for _, bootstrapNode := range n.config.BootstrapNodes {
		n.ConnectToPeer(bootstrapNode)
	}
	return nil
}

func (n *grpcInterface) Start() error {
	n.serverMutex.Lock()
	defer n.serverMutex.Unlock()
	log.Logger().Debugf("Starting gRPC P2P node (ID: %s)", n.config.PeerID)
	if n.config.ListenAddress != "" {
		log.Logger().Debugf("Starting gRPC server on %s", n.config.ListenAddress)
		serverOpts := []grpc.ServerOption{
			grpc.MaxRecvMsgSize(maxMessageSizeInBytes),
			grpc.MaxSendMsgSize(maxMessageSizeInBytes),
		}
		var err error
		n.listener, err = net.Listen("tcp", n.config.ListenAddress)
		if err != nil {
			return err
		}
		// Set ListenAddress to actual interface address resolved by `Listen()`
		n.config.ListenAddress = n.listener.Addr().String()
		// Configure TLS if enabled
		if n.config.tlsEnabled() {
			serverOpts = append(serverOpts, grpc.Creds(credentials.NewTLS(&tls.Config{
				Certificates: []tls.Certificate{n.config.ServerCert},
				ClientAuth:   tls.RequireAndVerifyClientCert,
				ClientCAs:    n.config.TrustStore,
			})))
		}
		n.grpcServer = grpc.NewServer(serverOpts...)
		transport.RegisterNetworkServer(n.grpcServer, n)
		go func() {
			err = n.grpcServer.Serve(n.listener)
			if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
				log.Logger().Errorf("gRPC server errored: %v", err)
				_ = n.Stop()
			}
		}()
	}
	// Start client
	go n.connectToNewPeers()
	return nil
}

func (n *grpcInterface) Stop() error {
	n.serverMutex.Lock()
	defer n.serverMutex.Unlock()
	// Stop client
	close(n.connectorAddChannel)
	n.connsMutex.Lock()
	{
		defer n.connsMutex.Unlock()
		for _, peer := range n.conns {
			peer.close()
		}
	}
	// Stop gRPC server
	if n.grpcServer != nil {
		n.grpcServer.Stop()
		n.grpcServer = nil
	}
	// Stop TCP listener
	if n.listener != nil {
		if err := n.listener.Close(); err != nil {
			log.Logger().Warn("Error while closing server listener: ", err)
		}
		n.listener = nil
	}
	return nil
}

func (n grpcInterface) ConnectToPeer(address string) bool {
	if n.shouldConnectTo(address) && len(n.connectorAddChannel) < connectingQueueChannelSize {
		n.connectorAddChannel <- address
		return true
	}
	return false
}

func (n *grpcInterface) startSendingAndReceiving(conn *connection) {
	conn.outMessages = make(chan *transport.NetworkMessage, 10) // TODO: Does this number make sense? Should also be configurable?
	go conn.sendMessages()
	n.registerConnection(conn)
	conn.receiveMessages(n.receivedMessages)
	// When we reach this line, receiveMessages has exited which means the connection has been closed.
	n.unregisterConnection(conn)
}

// connectToNewPeers reads from connectorAddChannel to start connecting to new peers
func (n *grpcInterface) connectToNewPeers() {
	for address := range n.connectorAddChannel {
		if _, present := n.peersByAddr[address]; present {
			log.Logger().Debugf("Not connecting to peer, already connected (address=%s)", address)
		} else if n.connectors[address] != nil {
			log.Logger().Debugf("Not connecting to peer, already trying to connect (address=%s)", address)
		} else {
			newConnector := &connector{
				address: address,
				backoff: defaultBackoff(),
				dialer:  n.grpcDialer,
			}
			n.connectors[address] = newConnector
			log.Logger().Debugf("Added remote peer (address=%s)", address)
			go n.startConnecting(newConnector)
		}
	}
}

func (n *grpcInterface) startConnecting(newConnector *connector) {
	for {
		if n.shouldConnectTo(newConnector.address) {
			var tlsConfig *tls.Config
			if n.config.tlsEnabled() {
				tlsConfig = &tls.Config{
					Certificates: []tls.Certificate{n.config.ClientCert},
					RootCAs:      n.config.TrustStore,
				}
			}
			if peer, err := newConnector.doConnect(n.config.PeerID, tlsConfig); err != nil {
				waitPeriod := newConnector.backoff.Backoff()
				log.Logger().Infof("Couldn't connect to peer, reconnecting in %d seconds (peer=%s,err=%v)", int(waitPeriod.Seconds()), newConnector.address, err)
				time.Sleep(waitPeriod)
			} else {
				n.startSendingAndReceiving(peer)
				newConnector.backoff.Reset()
			}
		}
	}
}

// shouldConnectTo checks whether we should connect to the given node.
func (n grpcInterface) shouldConnectTo(address string) bool {
	normalizedAddress := normalizeAddress(address)
	if normalizedAddress == normalizeAddress(n.getLocalAddress()) {
		// We're not going to connect to our own node
		log.Logger().Trace("Not connecting since it's localhost")
		return false
	}
	var alreadyConnected = true
	n.connsMutex.Lock()
	defer n.connsMutex.Unlock()
	if _, alreadyConnected = n.peersByAddr[normalizedAddress]; alreadyConnected {
		// We're not going to connect to a node we're already connected to
		log.Logger().Tracef("Not connecting since we're already connected (address=%s)", normalizedAddress)
	}
	return !alreadyConnected
}

func (n grpcInterface) getLocalAddress() string {
	if strings.HasPrefix(n.config.ListenAddress, ":") {
		// Interface's address not included in listening address (e.g. :5555), so prepend with localhost
		return "localhost" + n.config.ListenAddress
	} else {
		// Interface's address included in listening address (e.g. localhost:5555), so return as-is.
		return n.config.ListenAddress
	}
}

func (n grpcInterface) Connect(stream transport.Network_ConnectServer) error {
	peerCtx, _ := grpcPeer.FromContext(stream.Context())
	log.Logger().Tracef("New peer connected from %s", peerCtx.Addr)
	md, ok := metadata.FromIncomingContext(stream.Context())
	if !ok {
		return errors.New("unable to get metadata")
	}
	peerID, err := peerIDFromMetadata(md)
	if err != nil {
		return err
	}
	peer := Peer{
		ID:      peerID,
		Address: peerCtx.Addr.String(),
	}
	log.Logger().Infof("New peer connected (peer=%s)", peer)
	// We received our peer's PeerID, now send our own.
	if err := stream.SendHeader(constructMetadata(n.config.PeerID)); err != nil {
		return errors2.Wrap(err, "unable to send headers")
	}
	n.startSendingAndReceiving(createConnection(peer, stream))
	return nil
}

func (n *grpcInterface) registerConnection(conn *connection) {
	normalizedAddress := normalizeAddress(conn.Address)

	n.connsMutex.Lock()
	defer n.connsMutex.Unlock()

	n.conns[conn.ID] = conn
	n.peersByAddr[normalizedAddress] = conn.ID
	n.peerConnectedChannel <- conn.Peer
}

func (n *grpcInterface) unregisterConnection(conn *connection) {
	normalizedAddress := normalizeAddress(conn.Address)

	n.connsMutex.Lock()
	defer n.connsMutex.Unlock()

	conn = n.conns[conn.ID]
	if conn == nil {
		return
	}

	delete(n.conns, conn.ID)
	delete(n.peersByAddr, normalizedAddress)
	n.peerDisconnectedChannel <- conn.Peer
}
