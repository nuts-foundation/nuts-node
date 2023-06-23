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

package v2

import (
	"context"
	"errors"
	"fmt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-stoabs"
	"strings"
	"sync"
	"time"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/network/transport/v2/gossip"
	grpcLib "google.golang.org/grpc"

	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/nuts-foundation/nuts-node/network/transport/grpc"
	vdr "github.com/nuts-foundation/nuts-node/vdr/types"
)

var _ grpc.Protocol = (*protocol)(nil)

// Config specifies config for protocol v2
type Config struct {
	// Datadir from core.Config
	Datadir string
	// PayloadRetryDelay initial delay before retrying payload retrieval. Will grow exponentially
	PayloadRetryDelay time.Duration
	// GossipInterval specifies how often (in milliseconds) the node should broadcast its gossip message,
	// so other nodes can compare and synchronize.
	GossipInterval int `koanf:"gossipinterval"`
	// DiagnosticsInterval specifies how often (in milliseconds) the node should broadcast its diagnostics message.
	DiagnosticsInterval int `koanf:"diagnosticsinterval"`
}

const defaultPayloadRetryDelay = 5 * time.Second
const defaultGossipInterval = 5000
const defaultDiagnosticsInterval = 5000

// DefaultConfig returns the default config for protocol v2
func DefaultConfig() Config {
	return Config{
		PayloadRetryDelay:   defaultPayloadRetryDelay,
		GossipInterval:      defaultGossipInterval,
		DiagnosticsInterval: defaultDiagnosticsInterval,
	}
}

// New creates an instance of the v2 protocol.
func New(
	config Config,
	nodeDID did.DID,
	state dag.State,
	docResolver vdr.DocResolver,
	decrypter crypto.Decrypter,
	diagnosticsProvider func() transport.Diagnostics,
	dagStore stoabs.KVStore,
) transport.Protocol {
	ctx, cancel := context.WithCancel(context.Background())
	p := &protocol{
		cancel:      cancel,
		config:      config,
		ctx:         ctx,
		state:       state,
		nodeDID:     nodeDID,
		decrypter:   decrypter,
		docResolver: docResolver,
		dagStore:    dagStore,
	}
	p.sender = p
	p.diagnosticsMan = newPeerDiagnosticsManager(diagnosticsProvider, p.sender.broadcastDiagnostics)
	return p
}

type protocol struct {
	cancel                 func()
	config                 Config
	state                  dag.State
	ctx                    context.Context
	routines               *sync.WaitGroup
	docResolver            vdr.DocResolver
	privatePayloadReceiver dag.Notifier
	decrypter              crypto.Decrypter
	connectionList         grpc.ConnectionList
	nodeDID                did.DID
	connectionManager      transport.ConnectionManager
	cMan                   *conversationManager
	gManager               gossip.Manager
	diagnosticsMan         *peerDiagnosticsManager
	sender                 messageSender
	listHandler            *transactionListHandler
	dagStore               stoabs.KVStore
}

func (p *protocol) CreateClientStream(outgoingContext context.Context, grpcConn grpcLib.ClientConnInterface) (grpcLib.ClientStream, error) {
	return NewProtocolClient(grpcConn).Stream(outgoingContext)
}

func (p *protocol) Register(registrar grpcLib.ServiceRegistrar, acceptor func(stream grpcLib.ServerStream) error, connectionList grpc.ConnectionList, connectionManager transport.ConnectionManager) {
	RegisterProtocolServer(registrar, &protocolServer{acceptor: acceptor})
	p.connectionList = connectionList
	p.connectionManager = connectionManager
	p.connectionManager.RegisterObserver(p.connectionStateCallback)
}

func (p *protocol) Version() int {
	return 2
}

func (p *protocol) MethodName() string {
	return grpc.GetStreamMethod(Protocol_ServiceDesc.ServiceName, Protocol_ServiceDesc.Streams[0])
}

func (p *protocol) CreateEnvelope() interface{} {
	return &Envelope{}
}

func (p *protocol) UnwrapMessage(envelope interface{}) interface{} {
	return envelope.(*Envelope).Message
}

func (p *protocol) GetMessageType(envelope interface{}) string {
	if _, ok := envelope.(*Envelope); ok {
		result := fmt.Sprintf("%T", p.UnwrapMessage(envelope))
		return strings.TrimPrefix(result, "*v2.Envelope_")
	}
	return "unknown"
}

func (p *protocol) Configure(_ transport.PeerID) error {
	var err error
	if p.nodeDID.Empty() {
		log.Logger().Warn("Not starting the payload scheduler as node DID is not set")
	} else {
		p.privatePayloadReceiver, err = p.state.Notifier("private", func(event dag.Event) (bool, error) {
			return p.handlePrivateTxRetry(p.ctx, event)
		},
			dag.WithPersistency(p.dagStore),
			dag.WithRetryDelay(p.config.PayloadRetryDelay),
			dag.WithSelectionFilter(func(event dag.Event) bool {
				return event.Type == dag.TransactionEventType && event.Transaction.PAL() != nil
			}))
		if err != nil {
			return fmt.Errorf("failed to register transaction listener for private transactions: %w", err)
		}
	}

	// register gossip part of protocol
	p.gManager = gossip.NewManager(p.ctx, time.Duration(p.config.GossipInterval)*time.Millisecond)
	p.gManager.RegisterSender(p.sendGossip)

	// called after DAG is committed
	_, err = p.state.Notifier("gossip", p.gossipTransaction,
		dag.WithSelectionFilter(func(event dag.Event) bool {
			return event.Type == dag.TransactionEventType
		}),
		dag.WithContext(p.ctx))
	if err != nil {
		return fmt.Errorf("failed to register transaction listener for gossip: %w", err)
	}

	return nil
}

func (p *protocol) Start() (err error) {
	p.cMan = newConversationManager(maxValidity)
	p.cMan.start(p.ctx)
	p.routines = new(sync.WaitGroup)

	if p.config.DiagnosticsInterval > 0 {
		p.routines.Add(1)
		go func(w *sync.WaitGroup) {
			defer w.Done()
			p.diagnosticsMan.start(p.ctx, time.Duration(p.config.DiagnosticsInterval)*time.Millisecond)
		}(p.routines)
	}

	// Wrap listHandler function to supply the context to handleTransactionList.
	// It would be prettier to pass a context around in all protocol message handlers (since most use context.Background() for database access now),
	// but that is too big a change for now.
	p.listHandler = newTransactionListHandler(p.ctx, p.handleTransactionList)
	p.routines.Add(1)
	go func(w *sync.WaitGroup) {
		defer w.Done()
		p.listHandler.start()
	}(p.routines)

	return
}

func (p *protocol) connectionStateCallback(peer transport.Peer, state transport.StreamState, protocol transport.Protocol) {
	if protocol.Version() == p.Version() {
		switch state {
		case transport.StateConnected:
			xor, clock := p.state.XOR(dag.MaxLamportClock)
			p.gManager.PeerConnected(peer, xor, clock)
			p.diagnosticsMan.add(peer)
		case transport.StateDisconnected:
			p.diagnosticsMan.remove(peer)
			p.gManager.PeerDisconnected(peer)
		}
	}
}

// gossipTransaction is called when a transaction is added to the DAG
func (p *protocol) gossipTransaction(event dag.Event) (bool, error) {
	// race conditions may occur since the XOR may have been updated in parallel.
	// If this is the case, nodes will fall back to using the IBLT.
	xor, clock := p.state.XOR(dag.MaxLamportClock)
	p.gManager.TransactionRegistered(event.Hash, xor, clock)

	return true, nil
}

func (p *protocol) sendGossip(transportPeer transport.Peer, refs []hash.SHA256Hash, xor hash.SHA256Hash, clock uint32) bool {
	conn := p.connectionList.Get(grpc.ByConnected(), grpc.ByPeer(transportPeer))
	var err error

	if conn == nil {
		err = grpc.ErrNoConnection
	} else {
		err = p.sendGossipMsg(conn, refs, xor, clock)
	}

	if err != nil {
		log.Logger().
			WithError(err).
			WithField(core.LogFieldPeerID, transportPeer.ID.String()).
			Error("failed to send Gossip message")
		return false
	}

	// this will signal gManager to clear the queue
	return true
}

func (p *protocol) handlePrivateTxRetry(ctx context.Context, event dag.Event) (bool, error) {
	// Sanity check: if we have the payload, mark this job as finished
	isPresent, err := p.state.IsPayloadPresent(ctx, event.Transaction.PayloadHash())
	if err != nil {
		if !errors.As(err, new(stoabs.ErrDatabase)) {
			err = dag.EventFatal{err}
		}
		return false, fmt.Errorf("unable to read payload (tx=%s): %w", event.Hash, err)
	}

	if isPresent {
		// stop retrying
		log.Logger().
			WithField(core.LogFieldTransactionRef, event.Hash.String()).
			Debug("Transaction payload already present, not querying")
		return true, nil
	}

	epal := dag.EncryptedPAL(event.Transaction.PAL())

	pal, err := p.decryptPAL(ctx, epal)
	if err != nil {
		if !errors.As(err, new(stoabs.ErrDatabase)) {
			err = dag.EventFatal{err}
		}
		return false, fmt.Errorf("failed to decrypt PAL header (tx=%s): %w", event.Hash, err)
	}

	// We weren't able to decrypt the PAL, so it wasn't meant for us
	if pal == nil {
		// stop retrying
		return true, nil
	}

	// Broadcast query to all TX participants we've got a connection to
	sent := false
	for _, curr := range pal {
		conn := p.connectionList.Get(grpc.ByConnected(), grpc.ByNodeDID(curr), grpc.ByAuthenticated())
		if conn != nil {
			err = conn.Send(p, &Envelope{Message: &Envelope_TransactionPayloadQuery{
				TransactionPayloadQuery: &TransactionPayloadQuery{
					TransactionRef: event.Hash.Slice(),
				},
			}}, false)

			if err != nil {
				log.Logger().
					WithError(err).
					WithFields(conn.Peer().ToFields()).
					WithField(core.LogFieldTransactionRef, event.Hash.String()).
					Warn("Failed to send TransactionPayloadQuery msg to private TX participant")
			} else {
				sent = true
			}
		}
	}

	if !sent {
		return false, fmt.Errorf("no authenticated connection to any of the participants (tx=%s, PAL=%v)", event.Hash.String(), pal)
	}

	return false, nil
}

func (p *protocol) Stop() {
	if p.cancel != nil {
		p.cancel()
	}
	p.routines.Wait()
}

func (p *protocol) Diagnostics() []core.DiagnosticResult {
	if p.privatePayloadReceiver == nil {
		return []core.DiagnosticResult{}
	}
	// Feels weird to ignore the error here but diagnostics shouldn't fail
	failedJobs, err := p.privatePayloadReceiver.GetFailedEvents()
	if err != nil {
		log.Logger().
			WithError(err).
			Error("Failed to get failed jobs")
	}

	return []core.DiagnosticResult{&core.GenericDiagnosticResult{
		Title:   "payload_fetch_dlq",
		Outcome: failedJobs,
	}}
}

func (p *protocol) PeerDiagnostics() map[string]transport.Diagnostics {
	return p.diagnosticsMan.get()
}

// decryptPAL returns nil, nil if the PAL couldn't be decoded
func (p *protocol) decryptPAL(ctx context.Context, encrypted [][]byte) (dag.PAL, error) {

	if p.nodeDID.Empty() {
		return nil, errors.New("node DID is not set")
	}

	doc, _, err := p.docResolver.Resolve(p.nodeDID, nil)
	if err != nil {
		return nil, err
	}

	keyAgreementIDs := make([]string, len(doc.KeyAgreement))

	for i, keyAgreement := range doc.KeyAgreement {
		keyAgreementIDs[i] = keyAgreement.ID.String()
	}

	epal := dag.EncryptedPAL(encrypted)

	return epal.Decrypt(ctx, keyAgreementIDs, p.decrypter)
}

type protocolServer struct {
	acceptor func(grpcLib.ServerStream) error
}

func (p protocolServer) Stream(server Protocol_StreamServer) error {
	return p.acceptor(server)
}
