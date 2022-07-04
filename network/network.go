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
	"encoding/json"
	"errors"
	"fmt"
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/nuts-node/storage"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/events"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/nuts-foundation/nuts-node/network/transport/grpc"
	v2 "github.com/nuts-foundation/nuts-node/network/transport/v2"
	"github.com/nuts-foundation/nuts-node/vdr/doc"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"go.etcd.io/bbolt"
)

var _ Transactions = (*Network)(nil)

const (
	// ModuleName specifies the name of this module.
	ModuleName = "Network"
	// softwareID contains the name of the vendor/implementation that's published in the node's diagnostic information.
	softwareID        = "https://github.com/nuts-foundation/nuts-node"
	errEventFailedMsg = "failed to emit event for published transaction: %w"
)

// defaultBBoltOptions are given to bbolt, allows for package local adjustments during test
var defaultBBoltOptions = bbolt.DefaultOptions

// Network implements Transactions interface and Engine functions.
type Network struct {
	config              Config
	strictMode          bool
	protocols           []transport.Protocol
	connectionManager   transport.ConnectionManager
	state               dag.State
	privateKeyResolver  crypto.KeyResolver
	keyResolver         types.KeyResolver
	startTime           atomic.Value
	peerID              transport.PeerID
	didDocumentResolver types.DocResolver
	decrypter           crypto.Decrypter
	nodeDIDResolver     transport.NodeDIDResolver
	didDocumentFinder   types.DocFinder
	eventPublisher      events.Event
	subscribers         map[EventType]map[string]Receiver
	connectionStore     stoabs.KVStore
	storeProvider       storage.Provider
}

// NewNetworkInstance creates a new Network engine instance.
func NewNetworkInstance(
	config Config,
	keyResolver types.KeyResolver,
	privateKeyResolver crypto.KeyResolver,
	decrypter crypto.Decrypter,
	didDocumentResolver types.DocResolver,
	didDocumentFinder types.DocFinder,
	eventPublisher events.Event,
	storeProvider storage.Provider,
) *Network {
	return &Network{
		config:              config,
		decrypter:           decrypter,
		keyResolver:         keyResolver,
		privateKeyResolver:  privateKeyResolver,
		didDocumentResolver: didDocumentResolver,
		didDocumentFinder:   didDocumentFinder,
		nodeDIDResolver:     &transport.FixedNodeDIDResolver{},
		eventPublisher:      eventPublisher,
		storeProvider:       storeProvider,
		subscribers:         map[EventType]map[string]Receiver{},
	}
}

// Configure configures the Network subsystem
func (n *Network) Configure(config core.ServerConfig) error {
	var err error
	if n.state, err = dag.NewState(config.Datadir, dag.NewPrevTransactionsVerifier(), dag.NewTransactionSignatureVerifier(n.keyResolver)); err != nil {
		return fmt.Errorf("failed to configure state: %w", err)
	}

	n.strictMode = config.Strictmode
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

	// Resolve node DID
	if n.config.NodeDID != "" {
		// Node DID is set, configure it statically
		configuredNodeDID, err := did.ParseDID(n.config.NodeDID)
		if err != nil {
			return fmt.Errorf("configured NodeDID is invalid: %w", err)
		}
		n.nodeDIDResolver = &transport.FixedNodeDIDResolver{NodeDID: *configuredNodeDID}
	} else if !config.Strictmode {
		// If node DID is not set we can wire the automatic node DID resolver, which makes testing/workshops/development easier.
		// Might cause unexpected behavior though, so it can't be used in strict mode.
		log.Logger().Infof("Node DID not set, will be auto-discovered.")
		n.nodeDIDResolver = transport.NewAutoNodeDIDResolver(n.privateKeyResolver, n.didDocumentFinder)
	} else {
		log.Logger().Warnf("Node DID not set, sending/receiving private transactions is disabled.")
	}

	// Configure protocols
	// todo: correct config passing? (no defaults are not used in test context)
	v2Cfg := n.config.ProtocolV2
	v2Cfg.Datadir = config.Datadir

	// Register enabled protocols
	var candidateProtocols []transport.Protocol
	if n.protocols == nil {
		candidateProtocols = []transport.Protocol{
			v2.New(v2Cfg, n.nodeDIDResolver, n.state, n.didDocumentResolver, n.decrypter, n.collectDiagnostics),
		}
	} else {
		// Only set protocols if not already set: improves testability
		candidateProtocols = n.protocols
		n.protocols = nil
	}
	for _, protocol := range candidateProtocols {
		if n.config.IsProtocolEnabled(protocol.Version()) {
			n.protocols = append(n.protocols, protocol)
		}
	}

	for _, prot := range n.protocols {
		err := prot.Configure(n.peerID)
		if err != nil {
			return fmt.Errorf("error while configuring protocol %T: %w", prot, err)
		}
	}

	// Setup connection manager, load with bootstrap nodes
	if n.connectionManager == nil {
		grpcOpts := []grpc.ConfigOption{
			grpc.WithConnectionTimeout(time.Duration(n.config.ConnectionTimeout) * time.Millisecond),
		}
		// Configure TLS
		if n.config.EnableTLS {
			grpcOpts = append(grpcOpts, grpc.WithTLS(clientCert, trustStore, n.config.MaxCRLValidityDays))
		}

		// Instantiate
		var authenticator grpc.Authenticator
		if n.config.DisableNodeAuthentication {
			// Not allowed in strict mode for security reasons: only intended for demo/workshop purposes.
			if config.Strictmode {
				return errors.New("disabling node DID in strict mode is not allowed")
			}
			authenticator = grpc.NewDummyAuthenticator(doc.NewServiceResolver(n.didDocumentResolver))
		} else {
			authenticator = grpc.NewTLSAuthenticator(doc.NewServiceResolver(n.didDocumentResolver))
		}
		n.connectionStore, err = n.storeProvider.GetKVStore("connections")
		if err != nil {
			return fmt.Errorf("failed to open connections store: %w", err)
		}
		n.connectionManager = grpc.NewGRPCConnectionManager(
			grpc.NewConfig(n.config.GrpcAddr, n.peerID, grpcOpts...),
			n.connectionStore,
			n.nodeDIDResolver,
			authenticator,
			n.protocols...,
		)
	}

	// register callback from DAG to other engines, with payload only.
	n.state.RegisterPayloadObserver(n.emitEvents, true)

	// register observers to publish to other engines. Non-transactional, so will be published to other engines at most once.
	n.state.RegisterTransactionObserver(func(_ context.Context, transaction dag.Transaction) error {
		n.publish(TransactionAddedEvent, transaction, nil)
		return nil
	}, false)
	n.state.RegisterPayloadObserver(func(transaction dag.Transaction, payload []byte) error {
		n.publish(TransactionPayloadAddedEvent, transaction, payload)
		return nil
	}, false)

	return nil
}

// emitEvents is called when a transaction is being added to the DAG.
// It runs within the transactional context because if the event fails, the transaction must also fail.
// If the transaction fails for some reason (storage) then the event is still emitted. This is ok because the transaction was already validated.
// Most likely the transaction will be added at a later stage and another event will be emitted.
// It only emits events when both the payload and transaction are present. This is the case from both state.Add and from state.WritePayload.
func (n *Network) emitEvents(tx dag.Transaction, payload []byte) error {
	if tx != nil && payload != nil {
		_, js, err := n.eventPublisher.Pool().Acquire(context.Background())
		if err != nil {
			return fmt.Errorf(errEventFailedMsg, err)
		}

		twp := events.TransactionWithPayload{
			Transaction: tx,
			Payload:     payload,
		}
		twpData, err := json.Marshal(twp)
		if err != nil {
			return fmt.Errorf(errEventFailedMsg, err)
		}

		if _, err = js.PublishAsync(events.TransactionsSubject, twpData); err != nil {
			return fmt.Errorf(errEventFailedMsg, err)
		}
	}
	return nil
}

func loadCertificateAndTrustStore(moduleConfig Config) (tls.Certificate, *core.TrustStore, error) {
	clientCertificate, err := tls.LoadX509KeyPair(moduleConfig.CertFile, moduleConfig.CertKeyFile)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("unable to load node TLS client certificate (certfile=%s,certkeyfile=%s): %w", moduleConfig.CertFile, moduleConfig.CertKeyFile, err)
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

	if err := n.state.Start(); err != nil {
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
			if n.strictMode {
				return fmt.Errorf("invalid NodeDID configuration: %w", err)
			}
			log.Logger().Errorf("Node DID is invalid, exchanging private TXs will not work: %v", err)
		}
	}

	// Start connection management and protocols
	err = n.connectionManager.Start()
	if err != nil {
		return err
	}
	for _, prot := range n.protocols {
		if err = prot.Start(); err != nil {
			return err
		}
	}

	return n.connectToKnownNodes(nodeDID)
}

func (n *Network) connectToKnownNodes(nodeDID did.DID) error {
	// Start connecting to bootstrap nodes
	for _, bootstrapNode := range n.config.BootstrapNodes {
		if len(strings.TrimSpace(bootstrapNode)) == 0 {
			continue
		}
		n.connectionManager.Connect(bootstrapNode, transport.WithUnauthenticated())
	}

	if !n.config.EnableDiscovery {
		return nil
	}

	// start connecting to published NutsComm addresses
	otherNodes, err := n.didDocumentFinder.Find(doc.IsActive(), doc.ValidAt(time.Now()), doc.ByServiceType(transport.NutsCommServiceType))
	if err != nil {
		return err
	}
	for _, node := range otherNodes {
		if !nodeDID.Empty() && node.ID.Equals(nodeDID) {
			// Found local node, do not discover.
			continue
		}
	inner:
		for _, service := range node.Service {
			if service.Type == transport.NutsCommServiceType {
				var nutsCommStr string
				if err = service.UnmarshalServiceEndpoint(&nutsCommStr); err != nil {
					log.Logger().Warnf("failed to extract NutsComm address from service (did=%s): %v", node.ID.String(), err)
					continue inner
				}
				address, err := transport.ParseAddress(nutsCommStr)
				if err != nil {
					log.Logger().Warnf("invalid NutsComm address from service (did=%s, str=%s): %v", node.ID.String(), nutsCommStr, err)
					continue inner
				}
				log.Logger().Infof("Discovered Nuts node (address=%s), published by %s", address, node.ID)
				n.connectionManager.Connect(address)
			}
		}
	}
	return nil
}

func (n *Network) validateNodeDID(nodeDID did.DID) error {
	// Check if DID document can be resolved
	document, _, err := n.didDocumentResolver.Resolve(nodeDID, nil)
	if err != nil {
		return fmt.Errorf("DID document can't be resolved (did=%s): %w", nodeDID, err)
	}

	// Check if the key agreement keys can be resolved
	if len(document.KeyAgreement) == 0 {
		return fmt.Errorf("DID document does not contain a keyAgreement key, register a keyAgreement key (did=%s)", nodeDID)
	}
	for _, keyAgreement := range document.KeyAgreement {
		if !n.privateKeyResolver.Exists(keyAgreement.ID.String()) {
			return fmt.Errorf("keyAgreement private key is not present in key store, recover your key material or register a new keyAgreement key (did=%s,kid=%s)", nodeDID, keyAgreement.ID)
		}
	}

	// Check if the DID document has a resolvable NutsComm endpoint
	serviceResolver := doc.NewServiceResolver(n.didDocumentResolver)
	serviceRef := doc.MakeServiceReference(nodeDID, transport.NutsCommServiceType)
	_, err = serviceResolver.Resolve(serviceRef, doc.DefaultMaxServiceReferenceDepth)
	if err != nil {
		return fmt.Errorf("unable to resolve %s service endpoint, register it on the DID document (did=%s): %v", transport.NutsCommServiceType, nodeDID, err)
	}
	return nil
}

// Subscribe makes a subscription for the specified transaction type. The receiver is called when a transaction
// is received for the specified event and payload type.
func (n *Network) Subscribe(eventType EventType, payloadType string, receiver Receiver) {
	if _, ok := n.subscribers[eventType]; !ok {
		n.subscribers[eventType] = make(map[string]Receiver, 0)
	}
	oldSubscriber := n.subscribers[eventType][payloadType]
	n.subscribers[eventType][payloadType] = func(transaction dag.Transaction, payload []byte) error {
		// Chain subscribers in case there's more than 1
		if oldSubscriber != nil {
			if err := oldSubscriber(transaction, payload); err != nil {
				return err
			}
		}
		return receiver(transaction, payload)
	}
}

func (n *Network) publish(eventType EventType, transaction dag.Transaction, payload []byte) {
	subs := n.subscribers[eventType]
	if subs == nil {
		return
	}
	for _, payloadType := range []string{transaction.PayloadType(), AnyPayloadType} {
		receiver := subs[payloadType]
		if receiver == nil {
			continue
		}
		if err := receiver(transaction, payload); err != nil {
			log.Logger().Errorf("Transaction subscriber returned an error (ref=%s,type=%s): %v", transaction.Ref(), transaction.PayloadType(), err)
		}
	}
}

// GetTransaction retrieves the transaction for the given reference. If the transaction is not known, an error is returned.
func (n *Network) GetTransaction(transactionRef hash.SHA256Hash) (dag.Transaction, error) {
	return n.state.GetTransaction(context.Background(), transactionRef)
}

// GetTransactionPayload retrieves the transaction Payload for the given transaction. If the transaction or Payload is not found
// nil is returned.
func (n *Network) GetTransactionPayload(transactionRef hash.SHA256Hash) ([]byte, error) {
	transaction, err := n.state.GetTransaction(context.Background(), transactionRef)
	if err != nil {
		return nil, err
	}
	if transaction == nil {
		return nil, nil
	}
	return n.state.ReadPayload(context.Background(), transaction.PayloadHash())
}

// ListTransactionsInRange returns all transactions known to this Network instance with lamport clock value between startInclusive and endExclusive.
func (n *Network) ListTransactionsInRange(startInclusive uint32, endExclusive uint32) ([]dag.Transaction, error) {
	return n.state.FindBetweenLC(startInclusive, endExclusive)
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
	prevs := n.state.Heads(ctx)
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

	// Calculate clock value
	lamportClock, err := n.calculateLamportClock(ctx, prevs)
	if err != nil {
		return nil, fmt.Errorf("unable to calculate clock value for new transaction: %w", err)
	}

	// Create transaction
	unsignedTransaction, err := dag.NewTransaction(payloadHash, template.Type, prevs, pal, lamportClock)
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
	// Store in local State and publish it
	if err = n.state.Add(ctx, transaction, template.Payload); err != nil {
		return nil, fmt.Errorf("unable to add newly created transaction to State: %w", err)
	}
	log.Logger().Infof("Transaction created (ref=%s,type=%s,length=%d)", transaction.Ref(), template.Type, len(template.Payload))
	return transaction, nil
}

func (n *Network) calculateLamportClock(ctx context.Context, prevs []hash.SHA256Hash) (uint32, error) {
	// the root has 0
	if len(prevs) == 0 {
		return 0, nil
	}

	var clock uint32
	for _, prev := range prevs {
		// GetTransaction always supplies an LC value, either calculated or stored
		tx, err := n.state.GetTransaction(ctx, prev)
		if err != nil {
			return 0, err
		}
		if tx.Clock() > clock {
			clock = tx.Clock()
		}
	}

	// add one
	return clock + 1, nil
}

// Shutdown cleans up any leftover go routines
func (n *Network) Shutdown() error {
	// Stop protocols and connection manager
	for _, prot := range n.protocols {
		prot.Stop()
	}
	n.connectionManager.Stop()

	// Close State and underlying DBs
	if n.state != nil {
		err := n.state.Shutdown()
		if err != nil {
			return err
		}
		n.state = nil
	}
	return nil
}

// Diagnostics collects and returns diagnostics for the Network engine.
func (n *Network) Diagnostics() []core.DiagnosticResult {
	var results = make([]core.DiagnosticResult, 0)
	// Connection manager and protocols
	results = append(results, core.DiagnosticResultMap{Title: "connections", Items: n.connectionManager.Diagnostics()})
	for _, prot := range n.protocols {
		results = append(results, core.DiagnosticResultMap{Title: fmt.Sprintf("protocol_v%d", prot.Version()), Items: prot.Diagnostics()})
	}
	// DAG
	if graph, ok := n.state.(core.Diagnosable); ok {
		results = append(results, core.DiagnosticResultMap{Title: "state", Items: graph.Diagnostics()})
	}
	// NodeDID
	nodeDID, err := n.nodeDIDResolver.Resolve()
	if err != nil {
		log.Logger().Errorf("Unable to resolve node DID for diagnostics: %v", err)
	}
	results = append(results, core.GenericDiagnosticResult{
		Title:   "node_did",
		Outcome: nodeDID,
	})
	return results
}

// PeerDiagnostics returns a map containing diagnostic information of the node's peers. The key contains the remote peer's ID.
func (n *Network) PeerDiagnostics() map[transport.PeerID]transport.Diagnostics {
	result := make(map[transport.PeerID]transport.Diagnostics, 0)
	// We assume higher protocol versions (later in the slice) have better/more accurate diagnostics,
	// so for now they're copied over diagnostics of earlier versions, unless the entry is empty for that peer.
	// We assume the diagnostic result is empty when it lists no peers (since it has at least 1 peer: the local node).
	for _, prot := range n.protocols {
		for peerID, peerDiagnostics := range prot.PeerDiagnostics() {
			if _, exists := result[peerID]; !exists || len(peerDiagnostics.Peers) > 0 {
				result[peerID] = peerDiagnostics
			}
		}
	}
	return result
}

func (n *Network) Reprocess(contentType string) {
	batchSize := uint32(1000)

	log.Logger().Infof("Starting reprocess of %s", contentType)

	go func() {
		ctx := context.Background()
		_, js, err := n.eventPublisher.Pool().Acquire(context.Background())
		if err != nil {
			log.Logger().Errorf("Failed to start reprocessing transactions: %v", err)
		}

		lastLC := uint32(999)
		for i := uint32(0); (lastLC+uint32(1))%batchSize == 0; i++ {
			start := i * batchSize
			end := start + batchSize
			txs, err := n.state.FindBetweenLC(start, end)
			if err != nil {
				log.Logger().Errorf("Failed to Reprocess transactions (start: %d, end: %d): %v", start, end, err)
				return
			}

			for _, tx := range txs {
				if tx.PayloadType() == contentType {
					// add to Nats
					subject := fmt.Sprintf("%s.%s", events.ReprocessStream, contentType)
					payload, err := n.state.ReadPayload(ctx, tx.PayloadHash())
					if err != nil {
						log.Logger().Errorf("Failed to publish transaction (subject: %s, ref: %s): %v", subject, tx.Ref().String(), err)
						return
					}
					twp := events.TransactionWithPayload{
						Transaction: tx,
						Payload:     payload,
					}
					data, _ := json.Marshal(twp)
					log.Logger().Tracef("Publishing transaction (subject=%s, ref=%s)", subject, tx.Ref().String())
					_, err = js.PublishAsync(subject, data)
					if err != nil {
						log.Logger().Errorf("Failed to publish transaction (subject: %s, ref: %s): %v", subject, tx.Ref().String(), err)
						return
					}
				}
				lastLC = tx.Clock()
			}

			// give some time for Update transactions that require all read transactions to be closed
			time.Sleep(time.Second)
		}
	}()
}

func (n *Network) collectDiagnostics() transport.Diagnostics {
	result := transport.Diagnostics{
		Uptime:               time.Now().Sub(n.startTime.Load().(time.Time)),
		NumberOfTransactions: uint32(n.state.Statistics(context.Background()).NumberOfTransactions),
		SoftwareVersion:      fmt.Sprintf("%s (%s)", core.GitBranch, core.GitCommit),
		SoftwareID:           softwareID,
	}
	for _, peer := range n.connectionManager.Peers() {
		result.Peers = append(result.Peers, peer.ID)
	}
	return result
}

func (n *Network) isPayloadPresent(ctx context.Context, txRef hash.SHA256Hash) (bool, error) {
	tx, err := n.state.GetTransaction(ctx, txRef)
	if err != nil {
		return false, err
	}
	if tx == nil {
		return false, nil
	}
	return n.state.IsPayloadPresent(ctx, tx.PayloadHash())
}
