/*
 * Copyright (C) 2020. Nuts community
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
	"github.com/google/uuid"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/network/p2p"
	"github.com/nuts-foundation/nuts-node/network/proto"
	"github.com/pkg/errors"
	"sync"
	"time"
)

// ModuleName defines the name of this module
const ModuleName = "Network"

// NetworkEngine implements Network interface and Engine functions.
// TODO: Refactor Engine-structs to something more sane or rename this struct (#18)
type NetworkEngine struct {
	Config        Config
	configOnce    sync.Once
	p2pNetwork    p2p.P2PNetwork
	protocol      proto.Protocol
	documentGraph dag.DAG
	payloadStore  dag.PayloadStore
	keyStore      crypto.KeyStore
}

// NewNetworkInstance creates a new NetworkEngine engine instance.
func NewNetworkInstance(config Config, keyStore crypto.KeyStore) *NetworkEngine {
	result := &NetworkEngine{
		Config:     config,
		keyStore:   keyStore,
		p2pNetwork: p2p.NewP2PNetwork(),
		protocol:   proto.NewProtocol(),
	}
	return result
}

// Configure configures the NetworkEngine subsystem
func (n *NetworkEngine) Configure() error {
	var err error
	n.configOnce.Do(func() {
		if n.documentGraph, n.payloadStore, err = dag.NewBBoltDAG(n.Config.DatabaseFile); err != nil {
			return
		}
		peerID := p2p.PeerID(uuid.New().String())
		n.protocol.Configure(n.p2pNetwork, n.documentGraph, n.payloadStore, time.Duration(n.Config.AdvertHashesInterval)*time.Millisecond, peerID)
		networkConfig, p2pErr := n.buildP2PConfig(peerID)
		if p2pErr != nil {
			log.Logger().Warnf("Unable to build P2P layer config, NetworkEngine will be offline (reason: %v)", p2pErr)
			return
		}
		err = n.p2pNetwork.Configure(*networkConfig)
	})
	return err
}

// Start initiates the NetworkEngine subsystem
func (n *NetworkEngine) Start() error {
	if n.p2pNetwork.Configured() {
		// It's possible that the Nuts node isn't bootstrapped (e.g. Node CA certificate missing) but that shouldn't
		// prevent it from starting. In that case the NetworkEngine will be in 'offline mode', meaning it can be read from
		// and written to, but it will not try to connect to other peers.
		if err := n.p2pNetwork.Start(); err != nil {
			return err
		}
	} else {
		log.Logger().Warn("NetworkEngine is in offline mode (P2P layer not configured).")
	}
	n.protocol.Start()
	return nil
}

// Subscribe makes a subscription for the specified document type. The receiver is called when a document
// is received for the specified type.
func (n *NetworkEngine) Subscribe(documentType string, receiver dag.Receiver) {
	n.documentGraph.Subscribe(documentType, receiver)
}

// GetDocument retrieves the document for the given reference. If the document is not known, an error is returned.
func (n *NetworkEngine) GetDocument(documentRef hash.SHA256Hash) (dag.Document, error) {
	return n.documentGraph.Get(documentRef)
}

// GetDocumentPayload retrieves the document payload for the given document. If the document or payload is not found
// nil is returned.
func (n *NetworkEngine) GetDocumentPayload(documentRef hash.SHA256Hash) ([]byte, error) {
	document, err := n.documentGraph.Get(documentRef)
	if err != nil {
		return nil, err
	}
	return n.payloadStore.ReadPayload(document.Payload())
}

// ListDocuments returns all documents known to this NetworkEngine instance.
func (n *NetworkEngine) ListDocuments() ([]dag.Document, error) {
	return n.documentGraph.All()
}

// CreateDocument creates a new document with the specified payload, and signs it using the specified key.
// If the key should be inside the document (instead of being referred to) `attachKey` should be true.
func (n *NetworkEngine) CreateDocument(payloadType string, payload []byte, signingKeyID string, attachKey bool, timestamp time.Time, fieldOpts ...dag.FieldOpt) (dag.Document, error) {
	payloadHash := hash.SHA256Sum(payload)
	log.Logger().Infof("Creating document (payload hash=%s,type=%s,length=%d,signingKey=%s)", payloadHash, payloadType, len(payload), signingKeyID)
	// Create document
	prevs := n.documentGraph.Heads()
	unsignedDocument, err := dag.NewDocument(payloadHash, payloadType, prevs, fieldOpts...)
	if err != nil {
		return nil, fmt.Errorf("unable to create new document: %w", err)
	}
	// Sign it
	var document dag.Document
	var signer dag.DocumentSigner
	if attachKey {
		signer = dag.NewAttachedJWKDocumentSigner(n.keyStore, signingKeyID, n.keyStore)
	} else {
		signer = dag.NewDocumentSigner(n.keyStore, signingKeyID)
	}
	document, err = signer.Sign(unsignedDocument, timestamp)
	if err != nil {
		return nil, fmt.Errorf("unable to sign newly created document: %w", err)
	}
	// Store on local DAG and publish it
	if err = n.documentGraph.Add(document); err != nil {
		return nil, fmt.Errorf("unable to add newly created document to DAG: %w", err)
	}
	if err = n.payloadStore.WritePayload(payloadHash, payload); err != nil {
		return nil, fmt.Errorf("unable to store payload of newly created document: %w", err)
	}
	return document, nil
}

// Shutdown cleans up any leftover go routines
func (n *NetworkEngine) Shutdown() error {
	return n.p2pNetwork.Stop()
}

// Diagnostics collects and returns diagnostics for the NetworkEngine engine.
func (n *NetworkEngine) Diagnostics() []core.DiagnosticResult {
	var results = make([]core.DiagnosticResult, 0)
	results = append(results, n.protocol.Diagnostics()...)
	results = append(results, n.p2pNetwork.Diagnostics()...)
	if graph, ok := n.documentGraph.(core.Diagnosable); ok {
		results = append(results, graph.Diagnostics()...)
	}
	return results
}

func (n *NetworkEngine) buildP2PConfig(peerID p2p.PeerID) (*p2p.P2PNetworkConfig, error) {
	cfg := p2p.P2PNetworkConfig{
		ListenAddress:  n.Config.GrpcAddr,
		PublicAddress:  n.Config.PublicAddr,
		BootstrapNodes: n.Config.parseBootstrapNodes(),
		PeerID:         peerID,
	}
	var err error
	if cfg.TrustStore, err = n.Config.loadTrustStore(); err != nil {
		return nil, err
	}
	clientCertificate, err := tls.LoadX509KeyPair(n.Config.CertFile, n.Config.CertKeyFile)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to load node TLS client certificate (certFile=%s,certKeyFile=%s)", n.Config.CertFile, n.Config.CertKeyFile)
	}
	cfg.ClientCert = clientCertificate
	// Load TLS server certificate, only if enableTLS=true and gRPC server should be started.
	if n.Config.GrpcAddr != "" && n.Config.EnableTLS {
		cfg.ServerCert = cfg.ClientCert
	}
	return &cfg, nil
}
