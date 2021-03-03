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
	crypto2 "crypto"
	"crypto/tls"
	"fmt"
	"github.com/pkg/errors"
	"os"
	"path"
	"path/filepath"
	"time"

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
	p2pNetwork   p2p.P2PNetwork
	protocol     proto.Protocol
	graph        dag.DAG
	publisher    dag.Publisher
	payloadStore dag.PayloadStore
	keyStore     crypto.KeyStore
}

// NewNetworkInstance creates a new Network engine instance.
func NewNetworkInstance(config Config, keyStore crypto.KeyStore) *Network {
	result := &Network{
		config:     config,
		keyStore:   keyStore,
		p2pNetwork: p2p.NewP2PNetwork(),
		protocol:   proto.NewProtocol(),
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
	n.graph = dag.NewBBoltDAG(db)
	n.payloadStore = dag.NewBBoltPayloadStore(db)
	n.publisher = dag.NewReplayingDAGPublisher(n.payloadStore, n.graph)
	peerID := p2p.PeerID(uuid.New().String())
	n.protocol.Configure(n.p2pNetwork, n.graph, n.payloadStore, dag.NewTransactionSignatureVerifier(n.keyStore), time.Duration(n.config.AdvertHashesInterval)*time.Millisecond, peerID)
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
		// It's possible that the Nuts node isn't bootstrapped (e.g. Node CA certificate missing) but that shouldn't
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
	return n.graph.All()
}

// CreateTransaction creates a new transaction with the specified payload, and signs it using the specified key.
// If the key should be inside the transaction (instead of being referred to) `attachKey` should be true.
func (n *Network) CreateTransaction(payloadType string, payload []byte, signingKeyID string, attachKey crypto2.PublicKey, timestamp time.Time, fieldOpts ...dag.FieldOpt) (dag.Transaction, error) {
	payloadHash := hash.SHA256Sum(payload)
	log.Logger().Infof("Creating transaction (payload hash=%s,type=%s,length=%d,signingKey=%s)", payloadHash, payloadType, len(payload), signingKeyID)
	// Create transaction
	prevs := n.graph.Heads()
	unsignedTransaction, err := dag.NewTransaction(payloadHash, payloadType, prevs, fieldOpts...)
	if err != nil {
		return nil, fmt.Errorf("unable to create new transaction: %w", err)
	}
	// Sign it
	var transaction dag.Transaction
	var signer dag.TransactionSigner
	if attachKey != nil {
		signer = dag.NewAttachedJWKTransactionSigner(n.keyStore, signingKeyID, attachKey)
	} else {
		signer = dag.NewTransactionSigner(n.keyStore, signingKeyID)
	}
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

func (n *Network) buildP2PConfig(peerID p2p.PeerID) (*p2p.P2PNetworkConfig, error) {
	cfg := p2p.P2PNetworkConfig{
		ListenAddress:  n.config.GrpcAddr,
		PublicAddress:  n.config.PublicAddr,
		BootstrapNodes: n.config.BootstrapNodes,
		PeerID:         peerID,
	}
	clientCertificate, err := tls.LoadX509KeyPair(n.config.CertFile, n.config.CertKeyFile)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to load node TLS client certificate (certFile=%s,certKeyFile=%s)", n.config.CertFile, n.config.CertKeyFile)
	}
	cfg.ClientCert = clientCertificate
	if n.config.EnableTLS {
		if cfg.TrustStore, err = n.config.loadTrustStore(); err != nil {
			return nil, err
		}
		// Load TLS server certificate, only if enableTLS=true and gRPC server should be started.
		if n.config.GrpcAddr != "" {
			cfg.ServerCert = cfg.ClientCert
		}
	}
	return &cfg, nil
}
