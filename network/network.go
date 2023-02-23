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
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
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
	"github.com/nuts-foundation/nuts-node/network/transport/v2"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/vdr/didservice"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"go.etcd.io/bbolt"
)

var _ Transactions = (*Network)(nil)
var _ core.HealthCheckable = (*Network)(nil)

const (
	// ModuleName specifies the name of this module.
	ModuleName = "Network"
	// softwareID contains the name of the vendor/implementation that's published in the node's diagnostic information.
	softwareID        = "https://github.com/nuts-foundation/nuts-node"
	errEventFailedMsg = "failed to emit event for published transaction: %w"
	// health check keys
	healthTLS        = "tls"
	healthAuthConfig = "auth_config"
)

// defaultBBoltOptions are given to bbolt, allows for package local adjustments during test
var defaultBBoltOptions = bbolt.DefaultOptions

// Network implements Transactions interface and Engine functions.
type Network struct {
	config              Config
	certificate         tls.Certificate
	trustStore          *core.TrustStore
	strictMode          bool
	protocols           []transport.Protocol
	connectionManager   transport.ConnectionManager
	state               dag.State
	keyStore            crypto.KeyStore
	keyResolver         types.KeyResolver
	startTime           atomic.Value
	peerID              transport.PeerID
	didDocumentResolver types.DocResolver
	nodeDIDResolver     transport.NodeDIDResolver
	didDocumentFinder   types.DocFinder
	eventPublisher      events.Event
	storeProvider       storage.Provider
}

// CheckHealth performs health checks for the network engine.
func (n *Network) CheckHealth(ctx context.Context) map[string]core.Health {
	results := make(map[string]core.Health)
	if n.certificate.Leaf != nil {
		// TLS enabled, verify the configured certificate
		_, err := n.certificate.Leaf.Verify(x509.VerifyOptions{
			Roots:         core.NewCertPool(n.trustStore.RootCAs),
			Intermediates: core.NewCertPool(n.trustStore.IntermediateCAs),
		})
		if err != nil {
			results[healthTLS] = core.Health{
				Status:  core.HealthStatusDown,
				Details: err.Error(),
			}
		} else {
			results[healthTLS] = core.Health{
				Status: core.HealthStatusUp,
			}
		}
	}
	// auth_config checks that the node is correctly configured to be authenticated by others
	nodeDID, err := n.nodeDIDResolver.Resolve()
	if err != nil {
		// can only happen when not in strictmode and autoNodeDIDResolver fails
		results[healthAuthConfig] = core.Health{
			Status:  core.HealthStatusUnknown,
			Details: err.Error(),
		}
		return results
	}

	if nodeDID.Empty() {
		results[healthAuthConfig] = core.Health{
			Status:  core.HealthStatusUp,
			Details: "no node DID",
		}
		return results
	}

	if err = n.validateNodeDID(nodeDID); err != nil {
		results[healthAuthConfig] = core.Health{
			Status:  core.HealthStatusDown,
			Details: err.Error(),
		}
	} else {
		results[healthAuthConfig] = core.Health{
			Status: core.HealthStatusUp,
		}
	}
	return results
}

func (n *Network) Migrate() error {
	return n.state.Migrate()
}

// NewNetworkInstance creates a new Network engine instance.
func NewNetworkInstance(
	config Config,
	keyResolver types.KeyResolver,
	keyStore crypto.KeyStore,
	didDocumentResolver types.DocResolver,
	didDocumentFinder types.DocFinder,
	eventPublisher events.Event,
	storeProvider storage.Provider,
) *Network {
	return &Network{
		config:              config,
		keyResolver:         keyResolver,
		keyStore:            keyStore,
		didDocumentResolver: didDocumentResolver,
		didDocumentFinder:   didDocumentFinder,
		nodeDIDResolver:     &transport.FixedNodeDIDResolver{},
		eventPublisher:      eventPublisher,
		storeProvider:       storeProvider,
	}
}

// Configure configures the Network subsystem
func (n *Network) Configure(config core.ServerConfig) error {
	var err error
	dagStore, err := n.storeProvider.GetKVStore("data", storage.PersistentStorageClass)
	if err != nil {
		return fmt.Errorf("unable to create database: %w", err)
	}
	if n.state, err = dag.NewState(dagStore, dag.NewPrevTransactionsVerifier(), dag.NewTransactionSignatureVerifier(n.keyResolver)); err != nil {
		return fmt.Errorf("failed to configure state: %w", err)
	}

	n.strictMode = config.Strictmode
	n.peerID = transport.PeerID(uuid.New().String())

	// TLS
	if config.LegacyTLS.Enabled {
		n.certificate, err = config.TLS.LoadCertificate()
		if err != nil {
			return err
		}
		n.trustStore, err = config.TLS.LoadTrustStore()
		if err != nil {
			return err
		}
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
		log.Logger().Info("Node DID not set, will be auto-discovered.")
		n.nodeDIDResolver = transport.NewAutoNodeDIDResolver(n.keyStore, n.didDocumentFinder)
	} else {
		log.Logger().Warn("Node DID not set, sending/receiving private transactions is disabled.")
	}

	// Configure protocols
	// todo: correct config passing? (no defaults are not used in test context)
	v2Cfg := n.config.ProtocolV2
	v2Cfg.Datadir = config.Datadir

	// Register enabled protocols
	var candidateProtocols []transport.Protocol
	if n.protocols == nil {
		candidateProtocols = []transport.Protocol{
			v2.New(v2Cfg, n.nodeDIDResolver, n.state, n.didDocumentResolver, n.keyStore, n.collectDiagnosticsForPeers, dagStore),
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
			grpc.WithBackoff(func() grpc.Backoff {
				return grpc.BoundedBackoff(time.Second, n.config.MaxBackoff)
			}),
		}
		// Configure TLS
		var authenticator grpc.Authenticator
		if config.LegacyTLS.Enabled {
			grpcOpts = append(grpcOpts, grpc.WithTLS(n.certificate, n.trustStore, config.TLS.GetCRLMaxValidityDays()))
			if config.TLS.Offload == core.OffloadIncomingTLS {
				grpcOpts = append(grpcOpts, grpc.WithTLSOffloading(config.TLS.ClientCertHeaderName))
			}
			authenticator = grpc.NewTLSAuthenticator(didservice.NewServiceResolver(n.didDocumentResolver))
		} else {
			// Not allowed in strict mode for security reasons: only intended for demo/workshop purposes.
			if config.Strictmode {
				return errors.New("disabling TLS in strict mode is not allowed")
			}
			log.Logger().Warn("TLS is disabled, which is only meant for demo/workshop purposes!")
			authenticator = grpc.NewDummyAuthenticator(nil)
		}

		// Instantiate
		connectionStore, err := n.storeProvider.GetKVStore("connections", storage.VolatileStorageClass)
		if err != nil {
			return fmt.Errorf("failed to open connections store: %w", err)
		}
		n.connectionManager = grpc.NewGRPCConnectionManager(
			grpc.NewConfig(n.config.GrpcAddr, n.peerID, grpcOpts...),
			connectionStore,
			n.nodeDIDResolver,
			authenticator,
			n.protocols...,
		)
	}

	// register callback from DAG to other engines, with payload only.
	if _, err = n.state.Notifier("nats", n.emitEvents,
		dag.WithPersistency(dagStore),
		dag.WithSelectionFilter(func(event dag.Event) bool {
			return event.Type == dag.PayloadEventType
		})); err != nil {
		return err
	}

	return nil
}

// emitEvents is called when a payload is added.
func (n *Network) emitEvents(event dag.Event) (bool, error) {
	_, js, err := n.eventPublisher.Pool().Acquire(context.Background())
	if err != nil {
		return false, fmt.Errorf(errEventFailedMsg, err)
	}

	twp := events.TransactionWithPayload{
		Transaction: event.Transaction,
		Payload:     event.Payload,
	}
	twpData, err := json.Marshal(twp)
	if err != nil {
		return false, fmt.Errorf(errEventFailedMsg, err)
	}

	if _, err = js.PublishAsync(events.TransactionsSubject, twpData); err != nil {
		return false, fmt.Errorf(errEventFailedMsg, err)
	}

	return true, nil
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

	// Sanity check for configured node DID: can we resolve it and do we have the keys?
	nodeDID, err := n.nodeDIDResolver.Resolve()
	if err != nil {
		return err
	}
	if !nodeDID.Empty() {
		err = n.validateNodeDIDKeys(nodeDID)
		if err != nil && n.strictMode {
			return err
		}
	}

	for _, prot := range n.protocols {
		if err = prot.Start(); err != nil {
			return err
		}
	}
	// Start connection management and protocols
	err = n.connectionManager.Start()
	if err != nil {
		return err
	}
	return n.connectToKnownNodes(nodeDID)
}

func (n *Network) connectToKnownNodes(nodeDID did.DID) error {
	// Start connecting to bootstrap nodes
	for _, bootstrapNode := range n.config.BootstrapNodes {
		if len(strings.TrimSpace(bootstrapNode)) == 0 {
			continue
		}
		n.connectionManager.Connect(bootstrapNode)
	}

	if !n.config.EnableDiscovery {
		return nil
	}

	// start connecting to published NutsComm addresses
	otherNodes, err := n.didDocumentFinder.Find(didservice.IsActive(), didservice.ValidAt(time.Now()), didservice.ByServiceType(transport.NutsCommServiceType))
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
				var nutsCommUrl transport.NutsCommURL
				if err = service.UnmarshalServiceEndpoint(&nutsCommUrl); err != nil {
					log.Logger().
						WithError(err).
						WithField(core.LogFieldDID, node.ID.String()).
						Warn("Failed to extract NutsComm address from service")
					continue inner
				}
				log.Logger().
					WithField(core.LogFieldDID, node.ID.String()).
					WithField(core.LogFieldNodeAddress, nutsCommUrl.Host).
					Info("Discovered Nuts node")
				n.connectionManager.Connect(nutsCommUrl.Host)
			}
		}
	}
	return nil
}

func (n *Network) validateNodeDIDKeys(nodeDID did.DID) error {
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
		if !n.keyStore.Exists(keyAgreement.ID.String()) {
			return fmt.Errorf("keyAgreement private key is not present in key store, recover your key material or register a new keyAgreement key (did=%s,kid=%s)", nodeDID, keyAgreement.ID)
		}
	}
	return nil
}

func (n *Network) validateNodeDID(nodeDID did.DID) error {
	if err := n.validateNodeDIDKeys(nodeDID); err != nil {
		return err
	}

	// Check if the DID document has a resolvable and valid NutsComm endpoint
	serviceResolver := didservice.NewServiceResolver(n.didDocumentResolver)
	serviceRef := didservice.MakeServiceReference(nodeDID, transport.NutsCommServiceType)
	nutsCommService, err := serviceResolver.Resolve(serviceRef, didservice.DefaultMaxServiceReferenceDepth)
	if err != nil {
		return fmt.Errorf("unable to resolve %s service endpoint, register it on the DID document (did=%s): %v", transport.NutsCommServiceType, nodeDID, err)
	}
	var nutsCommURL transport.NutsCommURL
	if err = nutsCommService.UnmarshalServiceEndpoint(&nutsCommURL); err != nil {
		return fmt.Errorf("invalid %s service endpoint: %w", transport.NutsCommServiceType, err)
	}

	// Check certificate and confirm it contains the NutsComm address
	if n.certificate.Leaf == nil {
		return errors.New("missing TLS certificate")
	}
	if err = n.certificate.Leaf.VerifyHostname(nutsCommURL.Hostname()); err != nil {
		return fmt.Errorf("none of the DNS names in TLS certificate match the %s service endpoint (nodeDID=%s, %s=%s)", transport.NutsCommServiceType, nodeDID, transport.NutsCommServiceType, nutsCommURL.String())
	}

	return nil
}

// Subscribe registers a receiverFn with specific options.
// The receiver is called when a transaction is added to the DAG.
// It's only called if the given dag.NotificationFilter's match.
func (n *Network) Subscribe(name string, subscriber dag.ReceiverFn, options ...SubscriberOption) error {
	notifierOptions := make([]dag.NotifierOption, len(options))
	for i, o := range options {
		notifierOptions[i] = o()
	}

	_, err := n.state.Notifier(name, subscriber, notifierOptions...)
	return err
}

func (n *Network) Subscribers() []dag.Notifier {
	if n.state != nil {
		return n.state.Notifiers()
	}

	return []dag.Notifier{}
}

func (n *Network) CleanupSubscriberEvents(subscriberName, errorPrefix string) error {
	for _, subscriber := range n.Subscribers() {
		if subscriber.Name() == subscriberName {
			events, err := subscriber.GetFailedEvents()
			if err != nil {
				return err
			}
			for _, event := range events {
				if strings.HasPrefix(event.Error, errorPrefix) {
					if err := subscriber.Finished(event.Hash); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
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
		if errors.Is(err, dag.ErrTransactionNotFound) {
			// convert ErrPayloadNotFound for simpler error handling
			return nil, dag.ErrPayloadNotFound
		}
		return nil, err
	}
	return n.state.ReadPayload(context.Background(), transaction.PayloadHash())
}

// ListTransactionsInRange returns all transactions known to this Network instance with lamport clock value between startInclusive and endExclusive.
func (n *Network) ListTransactionsInRange(startInclusive uint32, endExclusive uint32) ([]dag.Transaction, error) {
	return n.state.FindBetweenLC(context.Background(), startInclusive, endExclusive)
}

// CreateTransaction creates a new transaction from the given template.
func (n *Network) CreateTransaction(ctx context.Context, template Template) (dag.Transaction, error) {
	payloadHash := hash.SHA256Sum(template.Payload)
	log.Logger().
		WithField(core.LogFieldTransactionType, template.Type).
		WithField(core.LogFieldTransactionPayloadHash, payloadHash).
		WithField(core.LogFieldTransactionPayloadLength, len(template.Payload)).
		WithField(core.LogFieldTransactionIsPrivate, len(template.Participants) > 0).
		WithField(core.LogFieldKeyID, template.Key.KID()).
		Debug("Creating transaction")

	// Assert that all additional prevs are present and its Payload is there
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

	// get head
	head, err := n.state.Head(ctx)
	prevs := make([]hash.SHA256Hash, 0)
	if err != nil {
		return nil, fmt.Errorf("unable to get current head of the DAG: %w", err)
	}
	if !head.Equals(hash.EmptyHash()) {
		prevs = append(prevs, head)
	} else if len(template.AdditionalPrevs) != 0 {
		return nil, fmt.Errorf("cannot have previous transactions on root transaction")
	}
	// and additional prevs
	prevs = append(prevs, template.AdditionalPrevs...)

	// Encrypt PAL, making the TX private (if participants are specified)
	var pal [][]byte
	if len(template.Participants) > 0 {
		pal, err = template.Participants.Encrypt(n.keyResolver)
		if err != nil {
			return nil, fmt.Errorf("unable to encrypt PAL header for new transaction: %w", err)
		}
	}

	// Calculate clock value
	// Todo: optimize with getting current Head. LC will always be Head LC + 1
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
	signer := dag.NewTransactionSigner(n.keyStore, template.Key, template.AttachKey)
	timestamp := time.Now()
	if !template.Timestamp.IsZero() {
		timestamp = template.Timestamp
	}
	transaction, err = signer.Sign(ctx, unsignedTransaction, timestamp)
	if err != nil {
		return nil, fmt.Errorf("unable to sign newly created transaction: %w", err)
	}
	// Store in local State and publish it
	if err = n.state.Add(ctx, transaction, template.Payload); err != nil {
		return nil, fmt.Errorf("unable to add newly created transaction to State: %w", err)
	}
	log.Logger().
		WithField(core.LogFieldTransactionRef, transaction.Ref()).
		WithField(core.LogFieldTransactionType, template.Type).
		WithField(core.LogFieldTransactionPayloadLength, len(template.Payload)).
		Info("Transaction created")
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

	err := n.state.Shutdown()
	if err != nil {
		return err
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
		log.Logger().
			WithError(err).
			Error("Unable to resolve node DID for diagnostics")
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

// ReprocessReport describes the reprocess exection.
type ReprocessReport struct {
	// reserved for future use
}

func (n *Network) Reprocess(ctx context.Context, contentType string) (*ReprocessReport, error) {
	log.Logger().Infof("Starting reprocess of %s", contentType)

	_, js, err := n.eventPublisher.Pool().Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("reprocess abort on message client: %w", err)
	}

	// The Lamport's clock stamps count from 0, with a step size of 1.
	const clockSteps = 1000
	for offset := 0; ; offset += clockSteps {
		end := offset + clockSteps
		if end >= 1<<30 {
			return nil, errors.New("reprocess abort on Lamport clock int overflow")
		}
		txs, err := n.state.FindBetweenLC(ctx, uint32(offset), uint32(end))
		if err != nil {
			return nil, fmt.Errorf("reprocess abort on transaction lookup, clock range [%d, %d): %w", offset, end, err)
		}

		for _, tx := range txs {
			if tx.PayloadType() != contentType {
				continue // filter
			}

			// add to Nats
			subject := fmt.Sprintf("%s.%s", events.ReprocessStream, contentType)
			payload, err := n.state.ReadPayload(ctx, tx.PayloadHash())
			if err != nil {
				return nil, fmt.Errorf("reprocess abort on transaction %#x payload %#x: %w", tx.Ref(), tx.PayloadHash(), err)
			}
			twp := events.TransactionWithPayload{
				Transaction: tx,
				Payload:     payload,
			}
			data, _ := json.Marshal(twp)
			log.Logger().
				WithField(core.LogFieldTransactionRef, tx.Ref()).
				WithField(core.LogFieldEventSubject, subject).
				Trace("Publishing transaction")
			_, err = js.PublishAsync(subject, data)
			if err != nil {
				return nil, fmt.Errorf("reprocess abort on transaction %#x publish: %w", tx.Ref(), err)
			}
		}

		if len(txs) == 0 {
			break
		}
		lastTick := txs[len(txs)-1].Clock()
		if int(uint(lastTick))+1 < end {
			break
		}

		// Workaround Nuts stoabs package which locks updates on any pending read
		// transactions.
		time.Sleep(time.Second)
	}

	// flush publish queue
	select {
	case <-js.PublishAsyncComplete():
		break
	case <-ctx.Done():
		return nil, fmt.Errorf("reprocess terminate before completing succesful: %w", ctx.Err())
	}

	return new(ReprocessReport), nil
}

func (n *Network) collectDiagnosticsForPeers() transport.Diagnostics {
	stateDiagnostics := n.state.Diagnostics()
	transactionCount := uint(0)
	for _, diagnostic := range stateDiagnostics {
		if diagnostic.Name() == dag.TransactionCountDiagnostic {
			transactionCount = diagnostic.Result().(uint)
		}
	}

	result := transport.Diagnostics{
		Uptime:               time.Since(n.startTime.Load().(time.Time)),
		NumberOfTransactions: uint32(transactionCount),
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
		if errors.Is(err, dag.ErrTransactionNotFound) {
			return false, nil
		}
		return false, err
	}
	return n.state.IsPayloadPresent(ctx, tx.PayloadHash())
}
