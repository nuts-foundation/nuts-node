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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/events"
	"github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/network/transport/v2/gossip"
	"go.etcd.io/bbolt"

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
}

const defaultPayloadRetryDelay = 5 * time.Second
const defaultGossipInterval = 5000

// DefaultConfig returns the default config for protocol v2
func DefaultConfig() Config {
	return Config{
		PayloadRetryDelay: defaultPayloadRetryDelay,
		GossipInterval:    defaultGossipInterval,
	}
}

// New creates an instance of the v2 protocol.
func New(
	config Config,
	nodeDIDResolver transport.NodeDIDResolver,
	state dag.State,
	docResolver vdr.DocResolver,
	decrypter crypto.Decrypter,
	eventPublisher events.Event,
) transport.Protocol {
	ctx, cancel := context.WithCancel(context.Background())
	p := &protocol{
		cancel:          cancel,
		config:          config,
		ctx:             ctx,
		state:           state,
		nodeDIDResolver: nodeDIDResolver,
		decrypter:       decrypter,
		docResolver:     docResolver,
		eventPublisher:  eventPublisher,
	}
	p.sender = p
	return p
}

type protocol struct {
	cancel            func()
	config            Config
	state             dag.State
	ctx               context.Context
	docResolver       vdr.DocResolver
	payloadScheduler  Scheduler
	decrypter         crypto.Decrypter
	connectionList    grpc.ConnectionList
	nodeDIDResolver   transport.NodeDIDResolver
	connectionManager transport.ConnectionManager
	cMan              *conversationManager
	gManager          gossip.Manager
	sender            messageSender
	eventPublisher    events.Event
}

func (p protocol) CreateClientStream(outgoingContext context.Context, grpcConn grpcLib.ClientConnInterface) (grpcLib.ClientStream, error) {
	return NewProtocolClient(grpcConn).Stream(outgoingContext)
}

func (p *protocol) Register(registrar grpcLib.ServiceRegistrar, acceptor func(stream grpcLib.ServerStream) error, connectionList grpc.ConnectionList, connectionManager transport.ConnectionManager) {
	RegisterProtocolServer(registrar, &protocolServer{acceptor: acceptor})
	p.connectionList = connectionList
	p.connectionManager = connectionManager
	p.connectionManager.RegisterObserver(p.connectionStateCallback)
}

func (p protocol) Version() int {
	return 2
}

func (p protocol) MethodName() string {
	return grpc.GetStreamMethod(Protocol_ServiceDesc.ServiceName, Protocol_ServiceDesc.Streams[0])
}

func (p protocol) CreateEnvelope() interface{} {
	return &Envelope{}
}

func (p protocol) UnwrapMessage(envelope interface{}) interface{} {
	return envelope.(*Envelope).Message
}

func (p *protocol) Configure(_ transport.PeerID) error {
	dbFile := path.Join(p.config.Datadir, "network", "payload_jobs.db")
	if err := os.MkdirAll(filepath.Dir(dbFile), os.ModePerm); err != nil {
		return fmt.Errorf("unable to setup database: %w", err)
	}

	db, err := bbolt.Open(dbFile, 0600, bbolt.DefaultOptions)
	if err != nil {
		return fmt.Errorf("unable to create BBolt database: %w", err)
	}

	p.payloadScheduler, err = NewPayloadScheduler(db, p.config.PayloadRetryDelay, p.handlePrivateTxRetry)
	if err != nil {
		return fmt.Errorf("failed to setup payload scheduler: %w", err)
	}

	// register gossip part of protocol
	p.gManager = gossip.NewManager(p.ctx, time.Duration(p.config.GossipInterval)*time.Millisecond)
	p.gManager.RegisterSender(p.sendGossip)

	// called after DAG is committed
	p.state.RegisterObserver(p.gossipTransaction, false)

	// register callback from DAG to other engines.
	p.state.RegisterObserver(p.emitEvents, true)

	return nil
}

func (p *protocol) Start() (err error) {
	p.cMan = newConversationManager(maxValidity)
	p.cMan.start(p.ctx)

	nodeDID, err := p.nodeDIDResolver.Resolve()
	if err != nil {
		log.Logger().WithError(err).Error("Failed to resolve node DID")
	}

	if nodeDID.Empty() {
		log.Logger().Warn("Not starting the payload scheduler as node DID is not set")
	} else {
		// load old payload query jobs
		if err = p.payloadScheduler.Run(); err != nil {
			return fmt.Errorf("failed to start retrying TransactionPayloadQuery: %w", err)
		}

		// todo replace with observer, underlying storage is persistent
		p.state.Subscribe(dag.TransactionAddedEvent, dag.AnyPayloadType, p.handlePrivateTx)
	}

	return
}

func (p *protocol) connectionStateCallback(peer transport.Peer, state transport.StreamState, protocol transport.Protocol) {
	if protocol.Version() == p.Version() {
		switch state {
		case transport.StateConnected:
			xor, clock := p.state.XOR(context.Background(), math.MaxUint32)
			p.gManager.PeerConnected(peer, xor, clock)
		case transport.StateDisconnected:
			p.gManager.PeerDisconnected(peer)
		}
	}
}

// gossipTransaction is called when a transaction is added to the DAG
func (p *protocol) gossipTransaction(ctx context.Context, tx dag.Transaction, _ []byte) error {
	if tx != nil { // can happen when payload is written for private TX
		xor, clock := p.state.XOR(ctx, math.MaxUint32)
		p.gManager.TransactionRegistered(tx.Ref(), xor, clock)
	}
	return nil
}

// TODO description
// This may be done within the TX, since it's already determined the TX valid. Buit something else failed like storage.
// No rollback is needed, the TX will come by later anyway.
func (p *protocol) emitEvents(ctx context.Context, tx dag.Transaction, payload []byte) error {
	// TODO other events for missing payload/tx
	if tx != nil && payload != nil {
		_, js, err := p.eventPublisher.Pool().Acquire(ctx)
		if err != nil {
			return fmt.Errorf("failed to emit event for published transaction: %w", err)
		}

		twp := events.TransactionWithPayload{
			Transaction: string(tx.Data()),
			Payload:     base64.StdEncoding.EncodeToString(payload),
		}
		twpData, err := json.Marshal(twp)
		if err != nil {
			return fmt.Errorf("failed to emit event for published transaction: %w", err)
		}

		// TODO: constants
		if _, err = js.PublishAsync("TRANSACTIONS.tx", twpData); err != nil {
			return fmt.Errorf("failed to emit event for published transaction: %w", err)
		}
	}
	return nil
}

func (p *protocol) sendGossip(id transport.PeerID, refs []hash.SHA256Hash, xor hash.SHA256Hash, clock uint32) bool {
	if err := p.sendGossipMsg(id, refs, xor, clock); err != nil {
		log.Logger().Errorf("failed to send Gossip message (peer=%s): %v", id, err)
		return false
	}

	// this will signal gManager to clear the queue
	return true
}

func (p *protocol) handlePrivateTx(tx dag.Transaction, _ []byte) error {
	if len(tx.PAL()) == 0 {
		// not for us, but for V1 protocol
		return nil
	}

	if err := p.payloadScheduler.Schedule(tx.Ref()); err != nil {
		// this means the underlying DB is broken
		log.Logger().Errorf("failed to add payload query retry job: %v", err)
		return err
	}
	return nil
}

func (p *protocol) handlePrivateTxRetry(hash hash.SHA256Hash) {
	if err := p.handlePrivateTxRetryErr(hash); err != nil {
		log.Logger().Errorf("retry of TransactionPayloadQuery failed: %v", err)
	}
}

func (p *protocol) handlePrivateTxRetryErr(hash hash.SHA256Hash) error {
	tx, err := p.state.GetTransaction(context.Background(), hash)
	if err != nil {
		return fmt.Errorf("failed to retrieve transaction (tx=:%s) from the DAG: %w", hash.String(), err)
	}

	if tx == nil {
		return fmt.Errorf("failed to find transaction (tx=:%s) in DAG", hash.String())
	}

	// Sanity check: if we have the payload, mark this job as finished
	payload, err := p.state.ReadPayload(context.Background(), tx.PayloadHash())
	if err != nil {
		return fmt.Errorf("unable to read payload (tx=%s): %w", hash, err)
	}

	if payload != nil {
		// stop retrying
		log.Logger().Infof("Transaction payload already present, not querying (tx=%s)", hash)
		return p.payloadScheduler.Finished(hash)
	}

	if len(tx.PAL()) == 0 {
		log.Logger().Infof("Transaction does not have a PAL, not querying (tx=%s)", hash)
		return p.payloadScheduler.Finished(hash)
	}

	epal := dag.EncryptedPAL(tx.PAL())

	pal, err := p.decryptPAL(epal)
	if err != nil {
		return fmt.Errorf("failed to decrypt PAL header (tx=%s): %w", tx.Ref(), err)
	}

	// We weren't able to decrypt the PAL, so it wasn't meant for us
	if pal == nil {
		// stop retrying
		if err = p.payloadScheduler.Finished(hash); err != nil {
			return err
		}
		return nil
	}

	// Broadcast query to all TX participants we've got a connection to
	sent := false
	for _, curr := range pal {
		conn := p.connectionList.Get(grpc.ByConnected(), grpc.ByNodeDID(curr))
		if conn != nil {
			err = conn.Send(p, &Envelope{Message: &Envelope_TransactionPayloadQuery{
				TransactionPayloadQuery: &TransactionPayloadQuery{
					TransactionRef: tx.Ref().Slice(),
				},
			}})

			if err != nil {
				log.Logger().Warnf("Failed to send TransactionPayloadQuery msg to private TX participant (tx=%s, PAL=%v): %v", hash.String(), pal, err)
			} else {
				sent = true
			}
		}
	}

	if !sent {
		return fmt.Errorf("no connection to any of the participants (tx=%s, PAL=%v)", hash.String(), pal)
	}

	return nil
}

func (p *protocol) Stop() {
	if p.payloadScheduler != nil {
		_ = p.payloadScheduler.Close()
	}

	if p.cancel != nil {
		p.cancel()
	}
}

func (p protocol) Diagnostics() []core.DiagnosticResult {
	// Feels weird to ignore the error here but diagnostics shouldn't fail
	failedJobs, err := p.payloadScheduler.GetFailedJobs()
	if err != nil {
		log.Logger().Errorf("failed to get failed jobs: %v", err)
	}

	return []core.DiagnosticResult{&core.GenericDiagnosticResult{
		Title:   "payload_fetch_dlq",
		Outcome: failedJobs,
	}}
}

func (p protocol) PeerDiagnostics() map[transport.PeerID]transport.Diagnostics {
	return make(map[transport.PeerID]transport.Diagnostics)
}

func (p *protocol) send(peer transport.Peer, message isEnvelope_Message) error {
	connection := p.connectionList.Get(grpc.ByPeerID(peer.ID))
	if connection == nil {
		return fmt.Errorf("unable to send msg, connection not found (peer=%s)", peer)
	}
	return connection.Send(p, &Envelope{Message: message})
}

// decryptPAL returns nil, nil if the PAL couldn't be decoded
func (p *protocol) decryptPAL(encrypted [][]byte) (dag.PAL, error) {
	nodeDID, err := p.nodeDIDResolver.Resolve()
	if err != nil {
		return nil, err
	}

	if nodeDID.Empty() {
		return nil, errors.New("node DID is not set")
	}

	doc, _, err := p.docResolver.Resolve(nodeDID, nil)
	if err != nil {
		return nil, err
	}

	keyAgreementIDs := make([]string, len(doc.KeyAgreement))

	for i, keyAgreement := range doc.KeyAgreement {
		keyAgreementIDs[i] = keyAgreement.ID.String()
	}

	epal := dag.EncryptedPAL(encrypted)

	return epal.Decrypt(keyAgreementIDs, p.decrypter)
}

type protocolServer struct {
	acceptor func(grpcLib.ServerStream) error
}

func (p protocolServer) Stream(server Protocol_StreamServer) error {
	return p.acceptor(server)
}
