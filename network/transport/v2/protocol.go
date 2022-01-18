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
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/nuts-foundation/go-did/did"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/log"
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
}

const defaultPayloadRetryDelay = 5 * time.Second

// DefaultConfig returns the default config for protocol v2
func DefaultConfig() Config {
	return Config{
		PayloadRetryDelay: defaultPayloadRetryDelay,
	}
}

// New creates an instance of the v2 protocol.
func New(
	config Config,
	nodeDIDResolver transport.NodeDIDResolver,
	graph dag.DAG,
	publisher dag.Publisher,
	payloadStore dag.PayloadStore,
	docResolver vdr.DocResolver,
	decrypter crypto.Decrypter,
) transport.Protocol {
	return &protocol{
		config:          config,
		graph:           graph,
		publisher:       publisher,
		nodeDIDResolver: nodeDIDResolver,
		payloadStore:    payloadStore,
		decrypter:       decrypter,
		docResolver:     docResolver,
	}
}

type protocol struct {
	cancel            func()
	config            Config
	graph             dag.DAG
	ctx               context.Context
	docResolver       vdr.DocResolver
	payloadScheduler  Scheduler
	payloadStore      dag.PayloadStore
	decrypter         crypto.Decrypter
	connectionList    grpc.ConnectionList
	publisher         dag.Publisher
	nodeDIDResolver   transport.NodeDIDResolver
	connectionManager transport.ConnectionManager
}

func (p protocol) CreateClientStream(outgoingContext context.Context, grpcConn grpcLib.ClientConnInterface) (grpcLib.ClientStream, error) {
	return NewProtocolClient(grpcConn).Stream(outgoingContext)
}

func (p *protocol) Register(registrar grpcLib.ServiceRegistrar, acceptor func(stream grpcLib.ServerStream) error, connectionList grpc.ConnectionList, connectionManager transport.ConnectionManager) {
	RegisterProtocolServer(registrar, &protocolServer{acceptor: acceptor})
	p.connectionList = connectionList
	p.connectionManager = connectionManager
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

	return nil
}

func (p *protocol) Start() (err error) {
	p.ctx, p.cancel = context.WithCancel(context.Background())

	// load old payload query jobs
	if err = p.payloadScheduler.Run(); err != nil {
		return fmt.Errorf("failed to start retrying TransactionPayloadQuery: %w", err)
	}

	p.publisher.Subscribe(dag.TransactionAddedEvent, dag.AnyPayloadType, p.handlePrivateTx)
	return
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
	tx, err := p.graph.Get(context.Background(), hash)
	if err != nil {
		return fmt.Errorf("failed to retrieve transaction (tx=:%s) from the DAG: %w", hash.String(), err)
	}

	if tx == nil {
		return fmt.Errorf("failed to find transaction (tx=:%s) in DAG", hash.String())
	}

	// Sanity check: if we have the payload, mark this job as finished
	payload, err := p.payloadStore.ReadPayload(context.Background(), tx.PayloadHash())
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

	pal, senderDID, err := p.decryptPAL(epal)
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

	conn := p.connectionList.Get(grpc.ByConnected(), grpc.ByNodeDID(senderDID))

	if conn == nil {
		return fmt.Errorf("unable to retrieve payload, no connection found (tx=%s, DID=%s)", hash.String(), senderDID)
	}

	err = conn.Send(p, &Envelope{Message: &Envelope_TransactionPayloadQuery{
		TransactionPayloadQuery: &TransactionPayloadQuery{
			TransactionRef: tx.Ref().Slice(),
		},
	}})
	if err != nil {
		return fmt.Errorf("failed to send TransactionPayloadQuery message(tx=%s, DID=%s): %w", hash.String(), senderDID, err)
	}

	return nil
}

func (p *protocol) Stop() {
	if p.payloadScheduler != nil {
		p.payloadScheduler.Close()
	}

	if p.cancel != nil {
		p.cancel()
	}
}

func (p protocol) Diagnostics() []core.DiagnosticResult {
	return nil
}

func (p protocol) PeerDiagnostics() map[transport.PeerID]transport.Diagnostics {
	return make(map[transport.PeerID]transport.Diagnostics)
}

func (p *protocol) send(peer transport.Peer, message isEnvelope_Message) error {
	connection := p.connectionList.Get(grpc.ByPeerID(peer.ID))
	if connection == nil {
		return fmt.Errorf("unable to send message, connection not found (peer=%s)", peer)
	}
	return connection.Send(p, &Envelope{Message: message})
}

// decryptPAL returns nil, nil if the PAL couldn't be decoded
func (p *protocol) decryptPAL(encrypted [][]byte) (dag.PAL, did.DID, error) {
	nodeDID, err := p.nodeDIDResolver.Resolve()
	if err != nil {
		return nil, did.DID{}, err
	}

	if nodeDID.Empty() {
		return nil, did.DID{}, errors.New("node DID is not set")
	}

	doc, _, err := p.docResolver.Resolve(nodeDID, nil)
	if err != nil {
		return nil, did.DID{}, err
	}

	keyAgreementIDs := make([]string, len(doc.KeyAgreement))

	for i, keyAgreement := range doc.KeyAgreement {
		keyAgreementIDs[i] = keyAgreement.ID.String()
	}

	epal := dag.EncryptedPAL(encrypted)

	pal, err := epal.Decrypt(keyAgreementIDs, p.decrypter)
	if err != nil {
		return nil, did.DID{}, err
	}

	if len(pal) == 0 {
		return nil, did.DID{}, nil
	}

	var senderDID did.DID

	for _, id := range pal {
		if !id.Equals(nodeDID) {
			senderDID = id
		}
	}

	if senderDID.Empty() {
		return nil, did.DID{}, errors.New("unable to find a sender in the PAL")
	}

	return pal, senderDID, nil
}

type protocolServer struct {
	acceptor func(grpcLib.ServerStream) error
}

func (p protocolServer) Stream(server Protocol_StreamServer) error {
	return p.acceptor(server)
}
