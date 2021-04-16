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

type Dialer func(ctx context.Context, target string, opts ...grpc.DialOption) (conn *grpc.ClientConn, err error)

const connectingQueueChannelSize = 100

type p2pNetwork struct {
	config P2PNetworkConfig

	grpcServer *grpc.Server
	listener   net.Listener

	// connectors contains the list of peers we're currently trying to connect to.
	connectors map[string]*connector
	// connectorAddChannel is used to communicate addresses of remote peers to connect to.
	connectorAddChannel chan string
	// conns is the list of active connections. Access MUST be wrapped in locking using connsMutex.
	conns map[PeerID]*connection
	// peersByAddr access MUST be wrapped in locking using connsMutex.
	peersByAddr      map[string]PeerID
	connsMutex       *sync.Mutex
	receivedMessages messageQueue
	grpcDialer       Dialer
	configured       bool
}

func (n p2pNetwork) Configured() bool {
	return n.configured
}

func (n p2pNetwork) Diagnostics() []core.DiagnosticResult {
	peers := n.Peers()
	return []core.DiagnosticResult{
		NumberOfPeersStatistic{NumberOfPeers: len(peers)},
		PeersStatistic{Peers: peers},
		OwnPeerIDStatistic{peerID: n.config.PeerID},
	}
}

func (n *p2pNetwork) Peers() []Peer {
	var result []Peer
	n.connsMutex.Lock()
	defer n.connsMutex.Unlock()
	for _, conn := range n.conns {
		result = append(result, conn.Peer)
	}
	return result
}

func (n *p2pNetwork) Broadcast(message *transport.NetworkMessage) {
	n.connsMutex.Lock()
	defer n.connsMutex.Unlock()
	for _, conn := range n.conns {
		conn.outMessages <- message
	}
}

func (n p2pNetwork) ReceivedMessages() MessageQueue {
	return n.receivedMessages
}

func (n p2pNetwork) Send(peerId PeerID, message *transport.NetworkMessage) error {
	// TODO: Can't we optimize this so that we don't need this lock? Maybe by (secretly) embedding a pointer to the peer in the peer ID?
	var conn *connection
	n.connsMutex.Lock()
	{
		defer n.connsMutex.Unlock()
		conn = n.conns[peerId]
	}
	if conn == nil {
		return fmt.Errorf("unknown peer: %s", peerId)
	}
	conn.outMessages <- message
	return nil
}

type connector struct {
	address string
	backoff Backoff
	Dialer
}

func (c *connector) connect(ownID PeerID, tlsConfig *tls.Config) (*connection, error) {
	log.Logger().Debugf("Connecting to peer: %v", c.address)
	cxt := metadata.NewOutgoingContext(context.Background(), constructMetadata(ownID))
	dialContext, _ := context.WithTimeout(cxt, 5*time.Second)
	dialOptions := []grpc.DialOption{
		grpc.WithBlock(),                 // Dial should block until connection succeeded (or time-out expired)
		grpc.WithReturnConnectionError(), // This option causes underlying errors to be returned when connections fail, rather than just "context deadline exceeded"
	}
	if tlsConfig != nil {
		dialOptions = append(dialOptions, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig))) // TLS authentication
	} else {
		dialOptions = append(dialOptions, grpc.WithInsecure()) // No TLS, requires 'insecure' flag
	}
	grpcConn, err := c.Dialer(dialContext, c.address, dialOptions...)
	if err != nil {
		return nil, errors2.Wrap(err, "unable to connect")
	}
	client := transport.NewNetworkClient(grpcConn)
	gate, err := client.Connect(cxt)
	if err != nil {
		log.Logger().Warnf("Failed to set up stream (peer address=%s): %v", c.address, err)
		_ = grpcConn.Close()
		return nil, err
	}

	conn := connection{
		Peer:       Peer{Address: c.address},
		grpcConn:   grpcConn,
		client:     client,
		gate:       gate,
		closeMutex: &sync.Mutex{},
	}
	if serverHeader, err := gate.Header(); err != nil {
		log.Logger().Warnf("Error receiving headers from server (peer=%s): %v", c.address, err)
		_ = grpcConn.Close()
		return nil, err
	} else {
		if serverPeerID, err := peerIDFromMetadata(serverHeader); err != nil {
			log.Logger().Warnf("Error parsing PeerID header from server (peer=%s): %v", c.address, err)
			_ = grpcConn.Close()
			return nil, err
		} else if serverPeerID == "" {
			log.Logger().Warnf("Server didn't send a peer ID, dropping connection (peer=%s)", c.address)
			_ = grpcConn.Close()
			return nil, err
		} else {
			conn.ID = serverPeerID
		}
	}
	log.Logger().Infof("Connected to peer (id=%s,addr=%s)", conn.ID, c.address)
	return &conn, nil
}

func NewP2PNetwork() P2PNetwork {
	return &p2pNetwork{
		conns:               make(map[PeerID]*connection, 0),
		peersByAddr:         make(map[string]PeerID, 0),
		connectors:          make(map[string]*connector, 0),
		connectorAddChannel: make(chan string, connectingQueueChannelSize), // TODO: Does this number make sense?
		connsMutex:          &sync.Mutex{},
		receivedMessages:    messageQueue{c: make(chan PeerMessage, 100)}, // TODO: Does this number make sense?
		grpcDialer:          grpc.DialContext,
	}
}

type messageQueue struct {
	c chan PeerMessage
}

func (m messageQueue) Get() PeerMessage {
	return <-m.c
}

func (n *p2pNetwork) Configure(config P2PNetworkConfig) error {
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

func (n *p2pNetwork) Start() error {
	log.Logger().Debugf("Starting gRPC P2P node (ID: %s)", n.config.PeerID)
	if n.config.ListenAddress != "" {
		log.Logger().Debugf("Starting gRPC server on %s", n.config.ListenAddress)
		var err error
		// We allow test code to set the listener to allow for in-memory (bufnet) channels
		var serverOpts = make([]grpc.ServerOption, 0)
		if n.listener == nil {
			n.listener, err = net.Listen("tcp", n.config.ListenAddress)
			if err != nil {
				return err
			}
			if n.config.tlsEnabled() {
				serverOpts = append(serverOpts, grpc.Creds(credentials.NewTLS(&tls.Config{
					Certificates: []tls.Certificate{n.config.ServerCert},
					ClientAuth:   tls.RequireAndVerifyClientCert,
					ClientCAs:    n.config.TrustStore,
				})))
			}
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

func (n *p2pNetwork) Stop() error {
	// Stop server
	if n.grpcServer != nil {
		n.grpcServer.Stop()
		n.grpcServer = nil
	}
	if n.listener != nil {
		if err := n.listener.Close(); err != nil {
			log.Logger().Warn("Error while closing server listener: ", err)
		}
		n.listener = nil
	}
	close(n.connectorAddChannel)
	// Stop client
	n.connsMutex.Lock()
	defer n.connsMutex.Unlock()
	for _, peer := range n.conns {
		peer.close()
	}
	return nil
}

func (n p2pNetwork) ConnectToPeer(address string) bool {
	if n.shouldConnectTo(address) && len(n.connectorAddChannel) < connectingQueueChannelSize {
		n.connectorAddChannel <- address
		return true
	}
	return false
}

func (n *p2pNetwork) startSendingAndReceiving(conn *connection) {
	conn.outMessages = make(chan *transport.NetworkMessage, 10) // TODO: Does this number make sense? Should also be configurable?
	go conn.sendMessages()
	n.registerConnection(conn)
	// TODO: Check PeerID sent by peer
	receiveMessages(conn.gate, conn.ID, n.receivedMessages)
	conn.close()
	// When we reach this line, receiveMessages has exited which means the connection has been closed.
	n.unregisterConnection(conn)
}

// connectToNewPeers reads from connectorAddChannel to start connecting to new peers
func (n *p2pNetwork) connectToNewPeers() {
	for address := range n.connectorAddChannel {
		if _, present := n.peersByAddr[address]; present {
			log.Logger().Debugf("Not connecting to peer, already connected (address=%s)", address)
		} else if n.connectors[address] != nil {
			log.Logger().Debugf("Not connecting to peer, already trying to connect (address=%s)", address)
		} else {
			newConnector := &connector{
				address: address,
				backoff: defaultBackoff(),
				Dialer:  n.grpcDialer,
			}
			n.connectors[address] = newConnector
			log.Logger().Debugf("Added remote peer (address=%s)", address)
			go func() {
				for {
					if n.shouldConnectTo(address) {
						var tlsConfig *tls.Config
						if n.config.tlsEnabled() {
							tlsConfig = &tls.Config{
								Certificates: []tls.Certificate{n.config.ClientCert},
								RootCAs:      n.config.TrustStore,
							}
						}
						if peer, err := newConnector.connect(n.config.PeerID, tlsConfig); err != nil {
							waitPeriod := newConnector.backoff.Backoff()
							log.Logger().Infof("Couldn't connect to peer, reconnecting in %d seconds (peer=%s,err=%v)", int(waitPeriod.Seconds()), newConnector.address, err)
							time.Sleep(waitPeriod)
						} else {
							n.startSendingAndReceiving(peer)
							newConnector.backoff.Reset()
						}
					}
					time.Sleep(5 * time.Second)
				}
			}()
		}
	}
}

// shouldConnectTo checks whether we should connect to the given node.
func (n p2pNetwork) shouldConnectTo(address string) bool {
	normalizedAddress := normalizeAddress(address)
	if normalizedAddress == normalizeAddress(n.getLocalAddress()) {
		// We're not going to connect to our own node
		log.Logger().Trace("Not connecting since it's localhost")
		return false
	}
	var result = true
	n.connsMutex.Lock()
	defer n.connsMutex.Unlock()
	if _, present := n.peersByAddr[normalizedAddress]; present {
		// We're not going to connect to a node we're already connected to
		log.Logger().Tracef("Not connecting since we're already connected (address=%s)", normalizedAddress)
		result = false
	}
	return result
}

func (n p2pNetwork) getLocalAddress() string {
	if strings.HasPrefix(n.config.ListenAddress, ":") {
			// Interface's address not included in listening address (e.g. :5555), so prepend with localhost
			return "localhost" + n.config.ListenAddress
		} else {
			// Interface's address included in listening address (e.g. localhost:5555), so return as-is.
			return n.config.ListenAddress
		}
}

func (n p2pNetwork) isRunning() bool {
	return n.grpcServer != nil
}

func (n p2pNetwork) Connect(stream transport.Network_ConnectServer) error {
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
	conn := &connection{
		Peer:       peer,
		gate:       stream,
		closeMutex: &sync.Mutex{},
	}
	n.startSendingAndReceiving(conn)
	return nil
}

func (n *p2pNetwork) registerConnection(conn *connection) {
	n.connsMutex.Lock()
	defer n.connsMutex.Unlock()

	n.conns[conn.ID] = conn
	n.peersByAddr[normalizeAddress(conn.Address)] = conn.ID
}

func (n *p2pNetwork) unregisterConnection(conn *connection) {
	n.connsMutex.Lock()
	defer n.connsMutex.Unlock()

	conn = n.conns[conn.ID]
	if conn == nil {
		return
	}

	delete(n.conns, conn.ID)
	delete(n.peersByAddr, normalizeAddress(conn.Address))
}
