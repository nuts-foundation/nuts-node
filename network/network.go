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
	"github.com/nuts-foundation/nuts-node/crl"
	"os"
	"path"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/pkg/errors"

	"github.com/google/uuid"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/network/p2p"
	"github.com/nuts-foundation/nuts-node/network/proto"
	"go.etcd.io/bbolt"
)

// boltDBFileMode holds the Unix file mode the created BBolt database files will have.
const boltDBFileMode = 0600

// softwareID contains the name of the vendor/implementation that's published in the node's diagnostic information.
const softwareID = "https://github.com/nuts-foundation/nuts-node"

const (
	// ModuleName specifies the name of this module.
	ModuleName = "Network"
)

// defaultBBoltOptions are given to bbolt, allows for package local adjustments during test
var defaultBBoltOptions = bbolt.DefaultOptions

// Network implements Transactions interface and Engine functions.
type Network struct {
	config                 Config
	lastTransactionTracker lastTransactionTracker
	p2pNetwork             p2p.Adapter
	protocol               proto.Protocol
	graph                  dag.DAG
	publisher              dag.Publisher
	payloadStore           dag.PayloadStore
	keyResolver            types.KeyResolver
	startTime              atomic.Value
	peerID                 p2p.PeerID
}

// Walk walks the DAG starting at the root, passing every transaction to `visitor`.
func (n *Network) Walk(visitor dag.Visitor) error {
	ctx := context.Background()
	root, err := n.graph.Root(ctx)
	if err != nil {
		return err
	}
	return n.graph.Walk(ctx, dag.NewBFSWalkerAlgorithm(), visitor, root)
}

// NewNetworkInstance creates a new Network engine instance.
func NewNetworkInstance(config Config, keyResolver types.KeyResolver) *Network {
	result := &Network{
		config:                 config,
		keyResolver:            keyResolver,
		p2pNetwork:             p2p.NewAdapter(),
		protocol:               proto.NewProtocol(),
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
	db, bboltErr := bbolt.Open(dbFile, boltDBFileMode, defaultBBoltOptions)
	if bboltErr != nil {
		return fmt.Errorf("unable to create BBolt database: %w", bboltErr)
	}

	n.graph = dag.NewBBoltDAG(db, dag.NewSigningTimeVerifier(), dag.NewPrevTransactionsVerifier(), dag.NewTransactionSignatureVerifier(n.keyResolver))
	n.payloadStore = dag.NewBBoltPayloadStore(db)
	n.publisher = dag.NewReplayingDAGPublisher(n.payloadStore, n.graph)
	n.peerID = p2p.PeerID(uuid.New().String())
	n.protocol.Configure(n.p2pNetwork, n.graph, n.publisher, n.payloadStore, n.collectDiagnostics,
		time.Duration(n.config.AdvertHashesInterval)*time.Millisecond,
		time.Duration(n.config.AdvertDiagnosticsInterval)*time.Millisecond,
		time.Duration(n.config.CollectMissingPayloadsInterval)*time.Millisecond,
		n.peerID)

	networkConfig, p2pErr := n.buildP2PConfig(n.peerID)
	if p2pErr != nil {
		log.Logger().Warnf("Unable to build P2P layer config, network will be offline (reason: %v)", p2pErr)
		return nil
	}

	return n.p2pNetwork.Configure(*networkConfig)
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

	if n.p2pNetwork.Configured() {
		// It's possible that the Nuts node isn't bootstrapped (e.g. TLS configuration incomplete) but that shouldn't
		// prevent it from starting. In that case the network will be in 'offline mode', meaning it can be read from
		// and written to, but it will not try to connect to other peers.
		if err := n.p2pNetwork.Start(); err != nil {
			return err
		}
	} else {
		log.Logger().Warn("Network engine is in offline mode (P2P layer not configured).")
	}

	n.protocol.Start()
	n.publisher.Subscribe(dag.AnyPayloadType, n.lastTransactionTracker.process)
	n.publisher.Start()

	if err := n.graph.Verify(context.Background()); err != nil {
		return err
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

// GetTransactionPayload retrieves the transaction payload for the given transaction. If the transaction or payload is not found
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

// CreateTransaction creates a new transaction with the specified payload, and signs it using the specified key.
// If the key should be inside the transaction (instead of being referred to) `attachKey` should be true.
func (n *Network) CreateTransaction(payloadType string, payload []byte, key crypto.Key, attachKey bool, timestamp time.Time, additionalPrevs []hash.SHA256Hash) (dag.Transaction, error) {
	payloadHash := hash.SHA256Sum(payload)
	log.Logger().Debugf("Creating transaction (payload hash=%s,type=%s,length=%d,signingKey=%s)", payloadHash, payloadType, len(payload), key.KID())

	// Assert that all additional prevs are present and its payload is there
	ctx := context.Background()
	for _, prev := range additionalPrevs {
		isPresent, err := n.isPayloadPresent(ctx, prev)
		if err != nil {
			return nil, err
		}
		if !isPresent {
			return nil, fmt.Errorf("additional prev is unknown or missing payload (prev=%s)", prev)
		}
	}

	// Create transaction
	prevs := n.lastTransactionTracker.heads()
	for _, addPrev := range additionalPrevs {
		prevs = append(prevs, addPrev)
	}
	unsignedTransaction, err := dag.NewTransaction(payloadHash, payloadType, prevs)
	if err != nil {
		return nil, fmt.Errorf("unable to create new transaction: %w", err)
	}
	// Sign it
	var transaction dag.Transaction
	var signer dag.TransactionSigner
	signer = dag.NewTransactionSigner(key, attachKey)
	transaction, err = signer.Sign(unsignedTransaction, timestamp)
	if err != nil {
		return nil, fmt.Errorf("unable to sign newly created transaction: %w", err)
	}
	// Store on local DAG and publish it
	if err = n.graph.Add(ctx, transaction); err != nil {
		return nil, fmt.Errorf("unable to add newly created transaction to DAG: %w", err)
	}
	if err = n.payloadStore.WritePayload(ctx, payloadHash, payload); err != nil {
		return nil, fmt.Errorf("unable to store payload of newly created transaction: %w", err)
	}
	log.Logger().Infof("Transaction created (ref=%s,type=%s,length=%d)", transaction.Ref(), payloadType, len(payload))
	return transaction, nil
}

// Shutdown cleans up any leftover go routines
func (n *Network) Shutdown() error {
	return n.p2pNetwork.Stop()
}

// Diagnostics collects and returns diagnostics for the Network engine.
func (n *Network) Diagnostics() []core.DiagnosticResult {
	var results = make([]core.DiagnosticResult, 0)
	results = append(results, n.protocol.Diagnostics()...)
	results = append(results, n.p2pNetwork.Diagnostics()...)
	if graph, ok := n.graph.(core.Diagnosable); ok {
		results = append(results, graph.Diagnostics()...)
	}
	return results
}

// PeerDiagnostics returns a map containing diagnostic information of the node's peers. The key contains the remote peer's ID.
func (n *Network) PeerDiagnostics() map[p2p.PeerID]proto.Diagnostics {
	return n.protocol.PeerDiagnostics()
}

func (n *Network) buildP2PConfig(peerID p2p.PeerID) (*p2p.AdapterConfig, error) {
	cfg := p2p.AdapterConfig{
		ListenAddress:  n.config.GrpcAddr,
		BootstrapNodes: n.config.BootstrapNodes,
		PeerID:         peerID,
	}

	if n.config.EnableTLS {
		clientCertificate, err := tls.LoadX509KeyPair(n.config.CertFile, n.config.CertKeyFile)
		if err != nil {
			return nil, errors.Wrapf(err, "unable to load node TLS client certificate (certfile=%s,certkeyfile=%s)", n.config.CertFile, n.config.CertKeyFile)
		}

		trustStore, err := core.LoadTrustStore(n.config.TrustStoreFile)
		if err != nil {
			return nil, err
		}

		cfg.ClientCert = clientCertificate
		cfg.TrustStore = trustStore.CertPool
		cfg.RevokedCertificateDB = crl.NewDB(500, trustStore.CRLEndpoints)

		// Load TLS server certificate, only if enableTLS=true and gRPC server should be started.
		if n.config.GrpcAddr != "" {
			cfg.ServerCert = cfg.ClientCert
		}
	} else {
		log.Logger().Info("TLS is disabled, make sure the Nuts Node is behind a TLS terminator which performs TLS authentication.")
	}

	return &cfg, nil
}

func (n *Network) collectDiagnostics() proto.Diagnostics {
	result := proto.Diagnostics{
		Uptime:               time.Now().Sub(n.startTime.Load().(time.Time)),
		NumberOfTransactions: uint32(n.graph.Statistics(context.Background()).NumberOfTransactions),
		SoftwareVersion:      core.GitCommit,
		SoftwareID:           softwareID,
	}
	for _, peer := range n.p2pNetwork.Peers() {
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
