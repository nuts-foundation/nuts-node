/*
 * Nuts node
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

package didnuts

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/nats-io/nats.go"
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vdr/didnuts/didstore"
	"sort"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/nuts-foundation/go-did/did"
	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/events"
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/vdr/log"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

// DIDDocumentType contains network transaction mime-type to identify a DID Document in the network.
const DIDDocumentType = "application/did+json"

// ErrThumbprintMismatch is returned when a transaction publishing a new DID is signed with a different key than the DID is generated from
var ErrThumbprintMismatch = errors.New("thumbprint of signing key does not match DID")

// Ambassador acts as integration point between VDR and network by sending DID Documents network and process
// DID Documents received through the network.
type Ambassador interface {
	// Configure instructs the ambassador to start receiving DID Documents from the network.
	Configure() error
	// Start the event listener
	Start() error
}

type ambassador struct {
	networkClient network.Transactions
	store         didstore.Store
	keyResolver   types.NutsKeyResolver
	didResolver   types.DIDResolver
	eventManager  events.Event
}

// NewAmbassador creates a new Ambassador,
func NewAmbassador(networkClient network.Transactions, didStore didstore.Store, eventManager events.Event) Ambassador {
	resolver := Resolver{Store: didStore}
	return &ambassador{
		networkClient: networkClient,
		store:         didStore,
		keyResolver:   dag.SourceTXKeyResolver{Resolver: resolver},
		didResolver:   &Resolver{Store: didStore},
		eventManager:  eventManager,
	}
}

func (n *ambassador) Configure() error {
	return nil
}

func (n *ambassador) Start() error {
	// This subscription is dependent on the network configure operation.
	// The network is configured/started after the VDR, so these calls can't be in Configure()
	err := n.networkClient.Subscribe("vdr", n.handleNetworkEvent,
		n.networkClient.WithPersistency(),
		network.WithSelectionFilter(func(event dag.Event) bool {
			return event.Type == dag.PayloadEventType && event.Transaction.PayloadType() == DIDDocumentType
		}))
	if err != nil {
		return err
	}

	stream := events.NewDisposableStream(
		fmt.Sprintf("%s_%s", events.ReprocessStream, "VDR"),
		[]string{fmt.Sprintf("%s.%s", events.ReprocessStream, DIDDocumentType)},
		network.MaxReprocessBufferSize)
	conn, _, err := n.eventManager.Pool().Acquire(context.Background())
	if err != nil {
		return fmt.Errorf("failed to subscribe to REPROCESS event stream: %w", err)
	}

	err = stream.Subscribe(conn, "VDR", fmt.Sprintf("%s.%s", events.ReprocessStream, DIDDocumentType), n.handleReprocessEvent)

	if err != nil {
		return fmt.Errorf("failed to subscribe to REPROCESS event stream: %v", err)
	}
	return nil
}

func (n *ambassador) handleReprocessEvent(msg *nats.Msg) {
	jsonBytes := msg.Data
	twp := events.TransactionWithPayload{}

	if err := msg.Ack(); err != nil {
		log.Logger().
			WithError(err).
			Error("Failed to process REPROCESS.application/did+json event: failed to ack message")
		return
	}

	if err := json.Unmarshal(jsonBytes, &twp); err != nil {
		log.Logger().
			WithError(err).
			Error("Failed to process REPROCESS.application/did+json event: failed to unmarshall data")
		return
	}

	if err := n.callback(twp.Transaction, twp.Payload); err != nil {
		log.Logger().
			WithError(err).
			Error("Failed to process REPROCESS.application/did+json event")
		return
	}
}

func (n *ambassador) handleNetworkEvent(event dag.Event) (bool, error) {
	if err := n.callback(event.Transaction, event.Payload); err != nil {
		if !errors.As(err, new(stoabs.ErrDatabase)) {
			// anything that is not a database error will not be retried
			return false, dag.EventFatal{err}
		}
		return false, err
	}
	return true, nil
}

// thumbprintAlg is used for creating public key thumbprints
var thumbprintAlg = crypto.SHA256

// callback gets called when new DIDDocuments are received by the network. All checks on the signature are already performed.
// This method will check the integrity of the DID document related to the public key used to sign the network TX.
// The rules are based on the Nuts RFC006
// payload should be a json encoded did.document
// Duplicates are handled as updates and will be merged. Merging two exactly the same DID Documents results in the original document.
func (n *ambassador) callback(tx dag.Transaction, payload []byte) error {
	log.Logger().
		WithField(core.LogFieldTransactionRef, tx.Ref()).
		Debug("Processing DID document received from Nuts Network")
	if err := checkTransactionIntegrity(tx); err != nil {
		return fmt.Errorf("could not process new DID Document: %w", err)
	}

	// Unmarshal the next/new proposed version of the DID Document
	var nextDIDDocument did.Document
	if err := json.Unmarshal(payload, &nextDIDDocument); err != nil {
		return fmt.Errorf("unable to unmarshal DID document from network payload: %w", err)
	}

	if err := NetworkDocumentValidator().Validate(nextDIDDocument); err != nil {
		return fmt.Errorf("callback could not process new DID Document, DID Document integrity check failed: %w", err)
	}

	// update documents
	var err error
	if n.isUpdate(tx) {
		err = n.handleUpdateDIDDocument(tx, nextDIDDocument)
	} else {
		err = n.handleCreateDIDDocument(tx, nextDIDDocument)
	}
	if err != nil {
		return err
	}

	// Notify network of DID update. At this point the updated document exists in the VDR and can be used for authentication.
	// Only inform network of a did update since nextDIDDocument could be received out of order, so may not be the latest version.
	n.networkClient.DiscoverServices(nextDIDDocument.ID)
	return nil
}

func (n *ambassador) handleCreateDIDDocument(transaction dag.Transaction, proposedDIDDocument did.Document) error {
	log.Logger().
		WithField(core.LogFieldTransactionRef, transaction.Ref()).
		WithField(core.LogFieldDID, proposedDIDDocument.ID).
		Debug("Handling DID document creation")
	// Check if the DID matches the fingerprint of the tx signing key:
	if transaction.SigningKey() == nil {
		return fmt.Errorf("callback could not process new DID Document: signingKey for new DID Documents must be set")
	}

	// Create key thumbprint from the transactions signingKey embedded in the header
	signingKeyThumbprint, err := nutsCrypto.Thumbprint(transaction.SigningKey())
	if err != nil {
		return fmt.Errorf("unable to generate thumbprint for network transaction signing key: %w", err)
	}

	// Check if signingKeyThumbprint equals the DID
	if proposedDIDDocument.ID.ID != signingKeyThumbprint {
		return ErrThumbprintMismatch
	}

	var rawKey crypto.PublicKey
	err = transaction.SigningKey().Raw(&rawKey)
	if err != nil {
		return err
	}

	err = n.store.Add(proposedDIDDocument, didstore.Transaction{
		Clock:       transaction.Clock(),
		PayloadHash: transaction.PayloadHash(),
		Previous:    transaction.Previous(),
		Ref:         transaction.Ref(),
		SigningTime: transaction.SigningTime(),
	})

	if err != nil {
		return fmt.Errorf("unable to register DID document: %w", err)
	}

	log.Logger().
		WithField(core.LogFieldTransactionRef, transaction.Ref()).
		WithField(core.LogFieldDID, proposedDIDDocument.ID.String()).
		Info("DID document registered")

	return nil
}

func (n *ambassador) handleUpdateDIDDocument(transaction dag.Transaction, proposedDIDDocument did.Document) error {
	log.Logger().
		WithField(core.LogFieldTransactionRef, transaction.Ref()).
		WithField(core.LogFieldDID, proposedDIDDocument.ID).
		Debug("Handling DID document update")

	// Resolve version of DID Document referred to by transaction
	var currentDIDDocument *did.Document
	var err error
	for _, ref := range transaction.Previous() {
		currentDIDDocument, _, err = n.store.Resolve(proposedDIDDocument.ID, &types.ResolveMetadata{AllowDeactivated: true, SourceTransaction: &ref})
		if err != nil && !errors.Is(err, types.ErrNotFound) {
			return fmt.Errorf("unable to update DID document: %w", err)
		}
		if currentDIDDocument != nil {
			break
		}
	}
	// fallback
	if currentDIDDocument == nil {
		currentDIDDocument, _, err = n.store.Resolve(proposedDIDDocument.ID, &types.ResolveMetadata{AllowDeactivated: true})
		if err != nil {
			return fmt.Errorf("unable to update DID document: %w", err)
		}
		log.Logger().Errorf("Failed to resolve DID Document by ref. Using latest version. (DID=%s)", proposedDIDDocument.ID)
	}

	// Resolve controllers of previous version (could be the same document)
	didControllers, err := n.resolveControllers(*currentDIDDocument, transaction)
	if err != nil {
		return fmt.Errorf("unable to resolve DID document's controllers: %w", err)
	}

	var controllerVerificationRelationships []did.VerificationRelationship
	for _, didCtrl := range didControllers {
		for _, capInv := range didCtrl.CapabilityInvocation {
			controllerVerificationRelationships = append(controllerVerificationRelationships, capInv)
		}
	}

	// In an update, only the keyID is provided in the network document. Resolve the key from the key store
	// This should succeed since the signature of the network document has already been verified.
	var pKey crypto.PublicKey
	pKey, err = n.keyResolver.ResolvePublicKey(transaction.SigningKeyID(), transaction.Previous())
	if err != nil {
		return fmt.Errorf("unable to resolve signingkey: %w", err)
	}

	signingKey, err := jwk.New(pKey)
	if err != nil {
		return fmt.Errorf("could not parse public key into jwk: %w", err)
	}
	// Create thumbprint
	signingKeyThumbprint, err := signingKey.Thumbprint(thumbprintAlg)
	if err != nil {
		return fmt.Errorf("unable to generate network document signing key thumbprint: %w", err)
	}

	// Check if the signingKey is listed as a valid capabilityInvocation in one of the controllers
	keyToSign, err := n.findKeyByThumbprint(signingKeyThumbprint, controllerVerificationRelationships)
	if err != nil {
		return fmt.Errorf("unable to find signingKey by thumprint in controllers: %w", err)
	}
	if keyToSign == nil {
		return fmt.Errorf("network document not signed by one of its controllers")
	}

	err = n.store.Add(proposedDIDDocument, didstore.Transaction{
		Clock:       transaction.Clock(),
		PayloadHash: transaction.PayloadHash(),
		Previous:    transaction.Previous(),
		Ref:         transaction.Ref(),
		SigningTime: transaction.SigningTime(),
	})

	if err == nil {
		log.Logger().
			WithField(core.LogFieldTransactionRef, transaction.Ref()).
			WithField(core.LogFieldDID, proposedDIDDocument.ID).
			Info("DID document updated")
	}
	return err
}

func (n *ambassador) resolveControllers(document did.Document, transaction dag.Transaction) ([]did.Document, error) {
	controllers := make([]did.Document, 0)
	signingTime := transaction.SigningTime()

	for _, prev := range transaction.Previous() {
		didControllers, err := ResolveControllers(n.didResolver, document, &types.ResolveMetadata{SourceTransaction: &prev})
		if err != nil {
			if errors.Is(err, types.ErrNotFound) || errors.Is(err, types.ErrNoActiveController) {
				continue
			}
			return nil, err
		}
		controllers = append(controllers, didControllers...)
	}

	// legacy resolve
	if len(controllers) == 0 {
		didControllers, err := ResolveControllers(n.didResolver, document, &types.ResolveMetadata{ResolveTime: &signingTime})
		if err != nil {
			return nil, err
		}
		controllers = append(controllers, didControllers...)
	}

	return controllers, nil
}

func sortHashes(input []hash.SHA256Hash) {
	sort.Slice(input, func(i, j int) bool {
		return bytes.Compare(input[i].Slice(), input[j].Slice()) < 0
	})
}

// missingTransactions does: current - incoming. Non conflicted updates will have an empty slice
func missingTransactions(current []hash.SHA256Hash, incoming []hash.SHA256Hash) []hash.SHA256Hash {
	j := 0
	for _, h := range current {
		found := false
		for _, h2 := range incoming {
			if h.Equals(h2) {
				found = true
				break
			}
		}
		if !found {
			current[j] = h
			j++
		}
	}

	return current[:j]
}

// uniqueTransactions does: Set(current + incoming).
func uniqueTransactions(current []hash.SHA256Hash, incoming hash.SHA256Hash) []hash.SHA256Hash {
	set := map[hash.SHA256Hash]bool{}
	for _, h := range current {
		set[h] = true
	}
	set[incoming] = true

	list := make([]hash.SHA256Hash, 0)
	for k := range set {
		list = append(list, k)
	}

	return list
}

// checkTransactionIntegrity performs basic integrity checks on the Transaction fields
// Some checks may look redundant because they are performed in the callers, this method has the sole
// responsibility to ensure integrity, while the other may have not.
func checkTransactionIntegrity(transaction dag.Transaction) error {
	// check the payload type:
	if transaction.PayloadType() != DIDDocumentType {
		return fmt.Errorf("wrong payload type for this subscriber. Can handle: %s, got: %s", DIDDocumentType, transaction.PayloadType())
	}

	// PayloadHash must be set
	if transaction.PayloadHash().Empty() {
		return fmt.Errorf("payloadHash must be provided")
	}

	// Signing time should be set:
	if transaction.SigningTime().IsZero() {
		return fmt.Errorf("signingTime must be set")
	}

	return nil
}

func (n ambassador) isUpdate(transaction dag.Transaction) bool {
	return transaction.SigningKey() == nil
}

// findKeyByThumbprint accepts a SHA256 generated thumbprint and tries to find it in a provided list of did.VerificationRelationship s.
// Returns an error if it could not generate a thumbprint of one of the VerificationRelationship keys
func (n ambassador) findKeyByThumbprint(thumbPrint []byte, didDocumentAuthKeys []did.VerificationRelationship) (jwk.Key, error) {
	var documentKey jwk.Key
	for _, key := range didDocumentAuthKeys {
		// Create thumbprint
		keyAsJWK, err := key.JWK()
		if err != nil {
			return nil, fmt.Errorf("unable to generate JWK from verificationMethod: %w", err)
		}
		documentThumbprint, err := keyAsJWK.Thumbprint(thumbprintAlg)
		if err != nil {
			return nil, fmt.Errorf("unable to generate DID document signing key thumbprint: %w", err)
		}
		// Compare thumbprints
		if bytes.Equal(thumbPrint, documentThumbprint) {
			documentKey = keyAsJWK
			break
		}
	}
	return documentKey, nil
}
