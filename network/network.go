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
	"crypto/tls"
	"fmt"
	"os"
	"path"
	"path/filepath"
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

const (
	moduleName = "Network"
	configKey  = "network"
)

// Network implements Transactions interface and Engine functions.
type Network struct {
	config       Config
	p2pNetwork   p2p.Adapter
	protocol     proto.Protocol
	graph        dag.DAG
	publisher    dag.Publisher
	payloadStore dag.PayloadStore
	keyResolver  types.KeyResolver
}

// Walk walks the DAG starting at the root, passing every transaction to `visitor`.
func (n *Network) Walk(visitor dag.Visitor) error {
	root, err := n.graph.Root()
	if err != nil {
		return err
	}
	return n.graph.Walk(dag.NewBFSWalkerAlgorithm(), visitor, root)
}

// NewNetworkInstance creates a new Network engine instance.
func NewNetworkInstance(config Config, keyResolver types.KeyResolver) *Network {
	result := &Network{
		config:      config,
		keyResolver: keyResolver,
		p2pNetwork:  p2p.NewAdapter(),
		protocol:    proto.NewProtocol(),
	}
	return result
}

// Configure configures the Network subsystem
func (n *Network) Configure(config core.ServerConfig) error {
	dbFile := path.Join(config.Datadir, "network", "data.db")
	if err := os.MkdirAll(filepath.Dir(dbFile), os.ModePerm); err != nil {
		return err
	}
	db, bboltErr := bbolt.Open(dbFile, boltDBFileMode, bbolt.DefaultOptions)
	if bboltErr != nil {
		return fmt.Errorf("unable to create BBolt database: %w", bboltErr)
	}
	n.graph = dag.NewBBoltDAG(db, dag.NewSigningTimeVerifier(), dag.NewPrevTransactionsVerifier(), dag.NewTransactionSignatureVerifier(n.keyResolver))
	n.payloadStore = dag.NewBBoltPayloadStore(db)
	n.publisher = dag.NewReplayingDAGPublisher(n.payloadStore, n.graph)
	peerID := p2p.PeerID(uuid.New().String())
	n.protocol.Configure(n.p2pNetwork, n.graph, n.publisher, n.payloadStore, time.Duration(n.config.AdvertHashesInterval)*time.Millisecond, peerID)
	networkConfig, p2pErr := n.buildP2PConfig(peerID)
	if p2pErr != nil {
		log.Logger().Warnf("Unable to build P2P layer config, network will be offline (reason: %v)", p2pErr)
		return nil
	}
	return n.p2pNetwork.Configure(*networkConfig)
}

// Name returns the module name.
func (n *Network) Name() string {
	return moduleName
}

// ConfigKey returns the config key for the module.
func (n *Network) ConfigKey() string {
	return configKey
}

// Config returns a pointer to the actual config of the module.
func (n *Network) Config() interface{} {
	return &n.config
}

// Start initiates the Network subsystem
func (n *Network) Start() error {
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
	n.publisher.Start()
	if err := n.graph.Verify(); err != nil {
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
	return n.graph.Get(transactionRef)
}

// GetTransactionPayload retrieves the transaction payload for the given transaction. If the transaction or payload is not found
// nil is returned.
func (n *Network) GetTransactionPayload(transactionRef hash.SHA256Hash) ([]byte, error) {
	transaction, err := n.graph.Get(transactionRef)
	if err != nil {
		return nil, err
	}
	return n.payloadStore.ReadPayload(transaction.PayloadHash())
}

// ListTransactions returns all transactions known to this Network instance.
func (n *Network) ListTransactions() ([]dag.Transaction, error) {
	return n.graph.FindBetween(dag.MinTime(), dag.MaxTime())
}

// CreateTransaction creates a new transaction with the specified payload, and signs it using the specified key.
// If the key should be inside the transaction (instead of being referred to) `attachKey` should be true.
func (n *Network) CreateTransaction(payloadType string, payload []byte, key crypto.Key, attachKey bool, timestamp time.Time, additionalPrevs []hash.SHA256Hash) (dag.Transaction, error) {
	payloadHash := hash.SHA256Sum(payload)
	log.Logger().Debugf("Creating transaction (payload hash=%s,type=%s,length=%d,signingKey=%s)", payloadHash, payloadType, len(payload), key.KID())

	// Create transaction
	prevs := n.graph.Heads()
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
	if err = n.graph.Add(transaction); err != nil {
		return nil, fmt.Errorf("unable to add newly created transaction to DAG: %w", err)
	}
	if err = n.payloadStore.WritePayload(payloadHash, payload); err != nil {
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
		cfg.ClientCert = clientCertificate
		if cfg.TrustStore, err = n.config.loadTrustStore(); err != nil {
			return nil, err
		}
		// Load TLS server certificate, only if enableTLS=true and gRPC server should be started.
		if n.config.GrpcAddr != "" {
			cfg.ServerCert = cfg.ClientCert
		}
	} else {
		log.Logger().Info("TLS is disabled, make sure the Nuts Node is behind a TLS terminator which performs TLS authentication.")
	}
	return &cfg, nil
}
