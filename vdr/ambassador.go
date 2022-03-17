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

package vdr

import (
	"bytes"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/vdr/doc"
	"github.com/nuts-foundation/nuts-node/vdr/log"
	"github.com/nuts-foundation/nuts-node/vdr/store"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

// didDocumentType contains network transaction mime-type to identify a DID Document in the network.
const didDocumentType = "application/did+json"

// ErrThumbprintMismatch is returned when a transaction publishing a new DID is signed with a different key than the DID is generated from
var ErrThumbprintMismatch = errors.New("thumbprint of signing key does not match DID")

// Ambassador acts as integration point between VDR and network by sending DID Documents network and process
// DID Documents received through the network.
type Ambassador interface {
	// Configure instructs the ambassador to start receiving DID Documents from the network.
	Configure()
}

type ambassador struct {
	networkClient network.Transactions
	didStore      types.Store
	keyResolver   types.KeyResolver
	docResolver   types.DocResolver
}

// NewAmbassador creates a new Ambassador,
func NewAmbassador(networkClient network.Transactions, didStore types.Store) Ambassador {
	return &ambassador{
		networkClient: networkClient,
		didStore:      didStore,
		keyResolver:   doc.KeyResolver{Store: didStore},
		docResolver:   doc.Resolver{Store: didStore},
	}
}

// Configure instructs the ambassador to start receiving DID Documents from the network.
func (n *ambassador) Configure() {
	n.networkClient.Subscribe(dag.TransactionPayloadAddedEvent, didDocumentType, n.callback)
}

// thumbprintAlg is used for creating public key thumbprints
var thumbprintAlg = crypto.SHA256

// callback gets called when new DIDDocuments are received by the network. All checks on the signature are already performed.
// This method will check the integrity of the DID document related to the public key used to sign the network TX.
// The rules are based on the Nuts RFC006
// payload should be a json encoded did.document
// Duplicates are handled as updates and will be merged. Merging two exactly the same DID Documents results in the original document.
func (n *ambassador) callback(tx dag.Transaction, payload []byte) error {
	log.Logger().Debugf("Processing DID document received from Nuts Network (ref=%s)", tx.Ref())
	if err := checkTransactionIntegrity(tx); err != nil {
		return fmt.Errorf("could not process new DID Document: %w", err)
	}

	// check if already processed
	processed, err := n.didStore.Processed(tx.Ref())
	if err != nil {
		return fmt.Errorf("could not process new DID Document: %w", err)
	}
	if processed {
		log.Logger().Infof("Skipping DID document, already exists (tx=%s)", tx.Ref().String())
		return nil
	}

	// Unmarshal the next/new proposed version of the DID Document
	var nextDIDDocument did.Document
	if err := json.Unmarshal(payload, &nextDIDDocument); err != nil {
		return fmt.Errorf("unable to unmarshal DID document from network payload: %w", err)
	}

	if err := CreateDocumentValidator().Validate(nextDIDDocument); err != nil {
		return fmt.Errorf("callback could not process new DID Document, DID Document integrity check failed: %w", err)
	}

	if n.isUpdate(tx) {
		return n.handleUpdateDIDDocument(tx, nextDIDDocument)
	}
	return n.handleCreateDIDDocument(tx, nextDIDDocument)
}

func (n *ambassador) handleCreateDIDDocument(transaction dag.Transaction, proposedDIDDocument did.Document) error {
	log.Logger().Debugf("Handling DID document creation (tx=%s,did=%s)", transaction.Ref(), proposedDIDDocument.ID)
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

	// check for an existing document, it could have been a parallel create. If existing merge and update.
	currentDIDDocument, currentDIDMeta, err := n.didStore.Resolve(proposedDIDDocument.ID, nil)
	if err != nil && !errors.Is(err, types.ErrNotFound) {
		return fmt.Errorf("unable to register DID document: %w", err)
	}
	sourceTransactions := []hash.SHA256Hash{transaction.Ref()}
	// pointer to updated time required for metadata, nil by default
	var updatedAtP *time.Time
	if currentDIDDocument != nil {
		mergedDoc, err := doc.MergeDocuments(*currentDIDDocument, proposedDIDDocument)
		if err != nil {
			return fmt.Errorf("unable to merge conflicted DID Document: %w", err)
		}
		proposedDIDDocument = *mergedDoc
		sourceTransactions = uniqueTransactions(currentDIDMeta.SourceTransactions, transaction.Ref())
		updatedAt := transaction.SigningTime()
		updatedAtP = &updatedAt
	}

	documentMetadata := types.DocumentMetadata{
		Created:            transaction.SigningTime(),
		Updated:            updatedAtP,
		Hash:               transaction.PayloadHash(),
		SourceTransactions: sourceTransactions,
	}

	if currentDIDDocument != nil {
		err = n.didStore.Update(currentDIDDocument.ID, currentDIDMeta.Hash, proposedDIDDocument, &documentMetadata)
	} else {
		err = n.didStore.Write(proposedDIDDocument, documentMetadata)
	}

	if err != nil {
		return fmt.Errorf("unable to register DID document: %w", err)
	}

	log.Logger().Infof("DID document registered (tx=%s,did=%s)", transaction.Ref(), proposedDIDDocument.ID)

	return nil
}

func (n *ambassador) handleUpdateDIDDocument(transaction dag.Transaction, proposedDIDDocument did.Document) error {
	log.Logger().Debugf("Handling DID document update (tx=%s,did=%s)", transaction.Ref(), proposedDIDDocument.ID)
	// Resolve latest version of DID Document
	currentDIDDocument, currentDIDMeta, err := n.didStore.Resolve(proposedDIDDocument.ID, nil)
	if err != nil {
		return fmt.Errorf("unable to update DID document: %w", err)
	}

	// Resolve controllers of current version (could be the same document)
	signingTime := transaction.SigningTime()
	didControllers, err := n.docResolver.ResolveControllers(*currentDIDDocument, &types.ResolveMetadata{ResolveTime: &signingTime})
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
	if signingTime.After(types.DIDDocumentResolveEpoch) {
		pKey, err = n.keyResolver.ResolvePublicKey(transaction.SigningKeyID(), transaction.Previous())
	} else {
		pKey, err = n.keyResolver.ResolvePublicKeyInTime(transaction.SigningKeyID(), &signingTime)
	}
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

	// check if the transactions contains all SourceTransactions
	missedTransactions := missingTransactions(currentDIDMeta.SourceTransactions, transaction.Previous())
	sourceTransactions := uniqueTransactions(missedTransactions, transaction.Ref())
	if len(missedTransactions) != 0 {
		mergedDoc, err := doc.MergeDocuments(*currentDIDDocument, proposedDIDDocument)
		if err != nil {
			return fmt.Errorf("unable to merge conflicted DID Document: %w", err)
		}
		proposedDIDDocument = *mergedDoc
	}

	// Stable order for metadata.SourceTransactions (derived from unordered maps): makes it easier to analyse and test.
	sortHashes(sourceTransactions)

	updatedAt := transaction.SigningTime()
	documentMetadata := types.DocumentMetadata{
		Created:            currentDIDMeta.Created,
		Updated:            &updatedAt,
		Hash:               transaction.PayloadHash(),
		PreviousHash:       &currentDIDMeta.Hash,
		Deactivated:        store.IsDeactivated(proposedDIDDocument),
		SourceTransactions: sourceTransactions,
	}
	err = n.didStore.Update(proposedDIDDocument.ID, currentDIDMeta.Hash, proposedDIDDocument, &documentMetadata)
	if err == nil {
		log.Logger().Infof("DID document updated (tx=%s,did=%s)", transaction.Ref(), proposedDIDDocument.ID)
	}
	return err
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
	if transaction.PayloadType() != didDocumentType {
		return fmt.Errorf("wrong payload type for this subscriber. Can handle: %s, got: %s", didDocumentType, transaction.PayloadType())
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
