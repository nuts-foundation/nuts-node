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

package network

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nuts-foundation/nuts-node/events"

	"github.com/google/uuid"
	"github.com/nuts-foundation/go-did/did"
	"github.com/pkg/errors"
	"go.etcd.io/bbolt"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/nuts-foundation/nuts-node/network/transport/grpc"
	"github.com/nuts-foundation/nuts-node/network/transport/v1"
	v2 "github.com/nuts-foundation/nuts-node/network/transport/v2"
	"github.com/nuts-foundation/nuts-node/vdr/doc"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

var _ Transactions = (*Network)(nil)

const (
	// boltDBFileMode holds the Unix file mode the created BBolt database files will have.
	boltDBFileMode = 0600
	// ModuleName specifies the name of this module.
	ModuleName = "Network"
	// softwareID contains the name of the vendor/implementation that's published in the node's diagnostic information.
	softwareID = "https://github.com/nuts-foundation/nuts-node"
)

// defaultBBoltOptions are given to bbolt, allows for package local adjustments during test
var defaultBBoltOptions = bbolt.DefaultOptions

// Network implements Transactions interface and Engine functions.
type Network struct {
	config                 Config
	lastTransactionTracker lastTransactionTracker
	protocols              []transport.Protocol
	connectionManager      transport.ConnectionManager
	graph                  dag.DAG
	publisher              dag.Publisher
	payloadStore           dag.PayloadStore
	privateKeyResolver     crypto.KeyResolver
	keyResolver            types.KeyResolver
	startTime              atomic.Value
	peerID                 transport.PeerID
	didDocumentResolver    types.DocResolver
	nodeDIDResolver        transport.NodeDIDResolver
	db                     *bbolt.DB
}

// Walk walks the DAG starting at the root, passing every transaction to `visitor`.
func (n *Network) Walk(visitor dag.Visitor) error {
	ctx := context.Background()
	return n.graph.Walk(ctx, visitor, hash.EmptyHash())
}

// NewNetworkInstance creates a new Network engine instance.
func NewNetworkInstance(config Config, keyResolver types.KeyResolver, privateKeyResolver crypto.KeyResolver, didDocumentResolver types.DocResolver) *Network {
	result := &Network{
		config:                 config,
		keyResolver:            keyResolver,
		privateKeyResolver:     privateKeyResolver,
		didDocumentResolver:    didDocumentResolver,
		nodeDIDResolver:        &transport.FixedNodeDIDResolver{},
		lastTransactionTracker: lastTransactionTracker{headRefs: make(map[hash.SHA256Hash]bool, 0)},
	}
	return result
}

// Configure configures the Network subsystem
func (n *Network) Configure(config core.ServerConfig) error {
	dbFile := path.Join(config.Datadir, "network", "data.db")
	if err := os.MkdirAll(filepath.Dir(dbFile), os.ModePerm); err != nil {
		return err
	}

	// for tests we set NoSync to true, this option can only be set through code
	var bboltErr error
	n.db, bboltErr = bbolt.Open(dbFile, boltDBFileMode, defaultBBoltOptions)
	if bboltErr != nil {
		return fmt.Errorf("unable to create BBolt database: %w", bboltErr)
	}

	n.graph = dag.NewBBoltDAG(n.db, dag.NewSigningTimeVerifier(), dag.NewPrevTransactionsVerifier(), dag.NewTransactionSignatureVerifier(n.keyResolver))
	// migrate DAG to add Clock values
	if err := n.graph.Migrate(); err != nil {
		return fmt.Errorf("unable to migrate DAG: %w", err)
	}

	// NATS
	conn, err := events.Connect(n.config.Nats.Hostname, n.config.Nats.Port, time.Duration(n.config.Nats.Timeout)*time.Second)
	if err != nil {
		return fmt.Errorf("unable to connect to NATS at '%s:%d': %w", n.config.Nats.Hostname, n.config.Nats.Port, err)
	}

	privateTxCtx, err := conn.JetStream()
	if err != nil {
		return fmt.Errorf("unable to connect to NATS at '%s:%d': %w", n.config.Nats.Hostname, n.config.Nats.Port, err)
	}

	n.payloadStore = dag.NewBBoltPayloadStore(n.db)
	n.publisher = dag.NewReplayingDAGPublisher(privateTxCtx, n.payloadStore, n.graph)
	n.peerID = transport.PeerID(uuid.New().String())

	// TLS
	var clientCert tls.Certificate
	var trustStore *core.TrustStore
	if n.config.EnableTLS {
		var err error
		clientCert, trustStore, err = loadCertificateAndTrustStore(n.config)
		if err != nil {
			return err
		}
	} else if len(n.config.CertFile) > 0 || len(n.config.CertKeyFile) > 0 {
		log.Logger().Warn("TLS is disabled but CertFile and/or CertKeyFile is set. Did you really mean to disable TLS?")
	}

	// Configure protocols
	n.protocols = []transport.Protocol{
		v1.New(n.config.ProtocolV1, n.graph, n.publisher, n.payloadStore, n.collectDiagnostics),
		v2.New(n.graph, n.payloadStore),
	}
	for _, prot := range n.protocols {
		prot.Configure(n.peerID)
	}
	// Setup connection manager, load with bootstrap nodes
	if n.connectionManager == nil {
		var grpcOpts []grpc.ConfigOption
		// Configure TLS
		if n.config.EnableTLS {
			grpcOpts = append(grpcOpts, grpc.WithTLS(clientCert, trustStore, n.config.MaxCRLValidityDays))
		}
		// Resolve node DID
		if n.config.NodeDID != "" {
			configuredNodeDID, err := did.ParseDID(n.config.NodeDID)
			if err != nil {
				return fmt.Errorf("configured NodeDID is invalid: %w", err)
			}
			n.nodeDIDResolver = &transport.FixedNodeDIDResolver{NodeDID: *configuredNodeDID}
		}
		// Instantiate
		n.connectionManager = grpc.NewGRPCConnectionManager(
			grpc.NewConfig(n.config.GrpcAddr, n.peerID, grpcOpts...),
			n.nodeDIDResolver,
			grpc.NewTLSAuthenticator(doc.NewServiceResolver(n.didDocumentResolver)),
			n.protocols...,
		)
	}
	return nil
}

func loadCertificateAndTrustStore(moduleConfig Config) (tls.Certificate, *core.TrustStore, error) {
	clientCertificate, err := tls.LoadX509KeyPair(moduleConfig.CertFile, moduleConfig.CertKeyFile)
	if err != nil {
		return tls.Certificate{}, nil, errors.Wrapf(err, "unable to load node TLS client certificate (certfile=%s,certkeyfile=%s)", moduleConfig.CertFile, moduleConfig.CertKeyFile)
	}
	trustStore, err := core.LoadTrustStore(moduleConfig.TrustStoreFile)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	return clientCertificate, trustStore, nil
}

// Name returns the module name.
func (n *Network) Name() string {
	return ModuleName
}

// Config returns a pointer to the actual config of the module.
func (n *Network) Config() interface{} {
	return &n.config
}

// Start initiates the Network subsystem
func (n *Network) Start() error {
	n.startTime.Store(time.Now())

	// Load DAG and start publishing
	n.publisher.Subscribe(dag.AnyPayloadType, n.lastTransactionTracker.process)
	n.publisher.Start()
	if err := n.graph.Verify(context.Background()); err != nil {
		return err
	}

	// Sanity check for configured node DID: can we resolve it?
	nodeDID, err := n.nodeDIDResolver.Resolve()
	if err != nil {
		return err
	}
	if !nodeDID.Empty() {
		err := n.validateNodeDID(nodeDID)
		if err != nil {
			return err
		}
	}

	// Start connection management and protocols
	err = n.connectionManager.Start()
	if err != nil {
		return err
	}
	for _, prot := range n.protocols {
		prot.Start()
	}

	// Start connecting to bootstrap nodes
	for _, bootstrapNode := range n.config.BootstrapNodes {
		if len(strings.TrimSpace(bootstrapNode)) == 0 {
			continue
		}
		n.connectionManager.Connect(bootstrapNode)
	}

	return nil
}

func (n *Network) validateNodeDID(nodeDID did.DID) error {
	// Check if DID document can be resolved
	document, _, err := n.didDocumentResolver.Resolve(nodeDID, nil)
	if err != nil {
		return fmt.Errorf("invalid NodeDID configuration: DID document can't be resolved (did=%s): %w", nodeDID, err)
	}

	// Check if the key agreement keys can be resolved
	if len(document.KeyAgreement) == 0 {
		return fmt.Errorf("invalid NodeDID configuration: DID document does not contain a keyAgreement key (did=%s)", nodeDID)
	}
	for _, keyAgreement := range document.KeyAgreement {
		if !n.privateKeyResolver.Exists(keyAgreement.ID.String()) {
			return fmt.Errorf("invalid NodeDID configuration: keyAgreement private key is not present in key store (did=%s,kid=%s)", nodeDID, keyAgreement.ID)
		}
	}

	// Check if the DID document has a resolvable NutsComm endpoint
	serviceResolver := doc.NewServiceResolver(n.didDocumentResolver)
	serviceRef := doc.MakeServiceReference(nodeDID, transport.NutsCommServiceType)
	_, err = serviceResolver.Resolve(serviceRef, doc.DefaultMaxServiceReferenceDepth)
	if err != nil {
		return fmt.Errorf("invalid NodeDID configuration: unable to resolve %s service endpoint (did=%s): %v", transport.NutsCommServiceType, nodeDID, err)
	}
	return nil
}

// Subscribe makes a subscription for the specified transaction type. The receiver is called when a transaction
// is received for the specified type.
func (n *Network) Subscribe(transactionType string, receiver dag.Receiver) {
	n.publisher.Subscribe(transactionType, receiver)
}

// GetTransaction retrieves the transaction for the given reference. If the transaction is not known, an error is returned.
func (n *Network) GetTransaction(transactionRef hash.SHA256Hash) (dag.Transaction, error) {
	return n.graph.Get(context.Background(), transactionRef)
}

// GetTransactionPayload retrieves the transaction Payload for the given transaction. If the transaction or Payload is not found
// nil is returned.
func (n *Network) GetTransactionPayload(transactionRef hash.SHA256Hash) ([]byte, error) {
	transaction, err := n.graph.Get(context.Background(), transactionRef)
	if err != nil {
		return nil, err
	}
	if transaction == nil {
		return nil, nil
	}
	return n.payloadStore.ReadPayload(context.Background(), transaction.PayloadHash())
}

// ListTransactions returns all transactions known to this Network instance.
func (n *Network) ListTransactions() ([]dag.Transaction, error) {
	return n.graph.FindBetween(context.Background(), dag.MinTime(), dag.MaxTime())
}

// CreateTransaction creates a new transaction from the given template.
func (n *Network) CreateTransaction(template Template) (dag.Transaction, error) {
	payloadHash := hash.SHA256Sum(template.Payload)
	log.Logger().Debugf("Creating transaction (payload hash=%s,type=%s,length=%d,signingKey=%s,private=%v)", payloadHash, template.Type, len(template.Payload), template.Key.KID(), len(template.Participants) > 0)

	// Assert that all additional prevs are present and its Payload is there
	ctx := context.Background()
	for _, prev := range template.AdditionalPrevs {
		isPresent, err := n.isPayloadPresent(ctx, prev)
		if err != nil {
			return nil, err
		}
		if !isPresent {
			return nil, fmt.Errorf("additional prev is unknown or missing payload (prev=%s)", prev)
		}
	}

	// Assert node DID is configured when participants are specified
	if len(template.Participants) > 0 {
		nodeDID, err := n.nodeDIDResolver.Resolve()
		if err != nil {
			return nil, err
		}
		if nodeDID.Empty() {
			return nil, errors.New("node DID must be configured to create private transactions")
		}
	}

	// Collect prevs
	prevs := n.lastTransactionTracker.heads()
	for _, addPrev := range template.AdditionalPrevs {
		prevs = append(prevs, addPrev)
	}

	// Encrypt PAL, making the TX private (if participants are specified)
	var pal [][]byte
	var err error
	if len(template.Participants) > 0 {
		pal, err = template.Participants.Encrypt(n.keyResolver)
		if err != nil {
			return nil, fmt.Errorf("unable to encrypt PAL header for new transaction: %w", err)
		}
	}

	// Create transaction
	unsignedTransaction, err := dag.NewTransaction(payloadHash, template.Type, prevs, pal)
	if err != nil {
		return nil, fmt.Errorf("unable to create new transaction: %w", err)
	}
	// Sign it
	var transaction dag.Transaction
	var signer dag.TransactionSigner
	signer = dag.NewTransactionSigner(template.Key, template.AttachKey)
	timestamp := time.Now()
	if !template.Timestamp.IsZero() {
		timestamp = template.Timestamp
	}
	transaction, err = signer.Sign(unsignedTransaction, timestamp)
	if err != nil {
		return nil, fmt.Errorf("unable to sign newly created transaction: %w", err)
	}
	// Store on local DAG and publish it
	if err = n.graph.Add(ctx, transaction); err != nil {
		return nil, fmt.Errorf("unable to add newly created transaction to DAG: %w", err)
	}
	if err = n.payloadStore.WritePayload(ctx, payloadHash, template.Payload); err != nil {
		return nil, fmt.Errorf("unable to store payload of newly created transaction: %w", err)
	}
	log.Logger().Infof("Transaction created (ref=%s,type=%s,length=%d)", transaction.Ref(), template.Type, len(template.Payload))
	return transaction, nil
}

// Shutdown cleans up any leftover go routines
func (n *Network) Shutdown() error {
	// Stop protocols and connection manager
	for _, prot := range n.protocols {
		prot.Stop()
	}
	n.connectionManager.Stop()

	// Close BBolt database
	if n.db != nil {
		err := n.db.Close()
		if err != nil {
			return err
		}
		n.db = nil
	}

	return nil
}

// Diagnostics collects and returns diagnostics for the Network engine.
func (n *Network) Diagnostics() []core.DiagnosticResult {
	var results = make([]core.DiagnosticResult, 0)
	results = append(results, n.connectionManager.Diagnostics()...)
	for _, prot := range n.protocols {
		results = append(results, prot.Diagnostics()...)
	}
	if graph, ok := n.graph.(core.Diagnosable); ok {
		results = append(results, graph.Diagnostics()...)
	}
	return results
}

// PeerDiagnostics returns a map containing diagnostic information of the node's peers. The key contains the remote peer's ID.
func (n *Network) PeerDiagnostics() map[transport.PeerID]transport.Diagnostics {
	result := make(map[transport.PeerID]transport.Diagnostics, 0)
	// We assume higher protocol versions (later in the slice) have better/more accurate diagnostics,
	// so for now they're copied over diagnostics of earlier versions.
	for _, prot := range n.protocols {
		for peerID, peerDiagnostics := range prot.PeerDiagnostics() {
			result[peerID] = peerDiagnostics
		}
	}
	return result
}

func (n *Network) collectDiagnostics() transport.Diagnostics {
	result := transport.Diagnostics{
		Uptime:               time.Now().Sub(n.startTime.Load().(time.Time)),
		NumberOfTransactions: uint32(n.graph.Statistics(context.Background()).NumberOfTransactions),
		SoftwareVersion:      core.GitCommit,
		SoftwareID:           softwareID,
	}
	for _, peer := range n.connectionManager.Peers() {
		result.Peers = append(result.Peers, peer.ID)
	}
	return result
}

func (n *Network) isPayloadPresent(ctx context.Context, txRef hash.SHA256Hash) (bool, error) {
	tx, err := n.graph.Get(ctx, txRef)
	if err != nil {
		return false, err
	}
	if tx == nil {
		return false, nil
	}
	return n.payloadStore.IsPresent(ctx, tx.PayloadHash())
}

// lastTransactionTracker that is used for tracking the heads but with payloads, since the DAG heads might have the associated payloads.
// This works because the publisher only publishes transactions which' payloads are present.
type lastTransactionTracker struct {
	headRefs map[hash.SHA256Hash]bool
	mux      sync.Mutex
}

func (l *lastTransactionTracker) process(transaction dag.Transaction, _ []byte) error {
	l.mux.Lock()
	defer l.mux.Unlock()

	// Update heads: previous' transactions aren't heads anymore, this transaction becomes a head.
	for _, prev := range transaction.Previous() {
		delete(l.headRefs, prev)
	}
	l.headRefs[transaction.Ref()] = true
	return nil
}

func (l *lastTransactionTracker) heads() []hash.SHA256Hash {
	l.mux.Lock()
	defer l.mux.Unlock()

	var heads []hash.SHA256Hash
	for head := range l.headRefs {
		heads = append(heads, head)
	}
	return heads
}
