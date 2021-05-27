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
	"time"

	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/vdr/doc"
	"github.com/nuts-foundation/nuts-node/vdr/logging"
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
	n.networkClient.Subscribe(didDocumentType, n.callback)
}

// thumbprintAlg is used for creating public key thumbprints
var thumbprintAlg = crypto.SHA256

// callback gets called when new DIDDocuments are received by the network. All checks on the signature are already performed.
// This method will check the integrity of the DID document related to the public key used to sign the network tr.
// The rules are based on the Nuts RFC006
// payload should be a json encoded did.document
func (n *ambassador) callback(tx dag.Transaction, payload []byte) error {
	logging.Log().Debugf("Processing DID document received from Nuts Network (ref=%s)", tx.Ref())
	if err := checkTransactionIntegrity(tx); err != nil {
		return fmt.Errorf("callback could not process new DID Document: %w", err)
	}

	// Unmarshal the next/new proposed version of the DID Document
	var nextDIDDocument did.Document
	if err := json.Unmarshal(payload, &nextDIDDocument); err != nil {
		return fmt.Errorf("unable to unmarshal DID document from network payload: %w", err)
	}

	if err := CreateDocumentValidator().Validate(nextDIDDocument); err != nil {
		return fmt.Errorf("callback could not process new DID Document, DID Document integrity check failed: %w", err)
	}

	isUpdate, err := n.isUpdate(nextDIDDocument)
	if err != nil {
		return fmt.Errorf("callback could not process new DID Document, failed to resolve current DID Document: %w", err)
	}

	if isUpdate {
		return n.handleUpdateDIDDocument(tx, nextDIDDocument)
	}
	return n.handleCreateDIDDocument(tx, nextDIDDocument)
}

func (n *ambassador) handleCreateDIDDocument(transaction dag.Transaction, proposedDIDDocument did.Document) error {
	logging.Log().Debugf("Handling DID document creation (tx=%s,did=%s)", transaction.Ref(), proposedDIDDocument.ID)
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

	documentMetadata := types.DocumentMetadata{
		Created:            transaction.SigningTime(),
		Hash:               transaction.PayloadHash(),
		SourceTransactions: []hash.SHA256Hash{transaction.Ref()},
	}
	err = n.didStore.Write(proposedDIDDocument, documentMetadata)
	if err == nil {
		logging.Log().Infof("DID document registered (tx=%s,did=%s)", transaction.Ref(), proposedDIDDocument.ID)
	}
	return err
}

func (n *ambassador) handleUpdateDIDDocument(transaction dag.Transaction, proposedDIDDocument did.Document) error {
	logging.Log().Debugf("Handling DID document update (tx=%s,did=%s)", transaction.Ref(), proposedDIDDocument.ID)
	// Resolve latest version of DID Document
	currentDIDDocument, currentDIDMeta, err := n.didStore.Resolve(proposedDIDDocument.ID, nil)
	if err != nil {
		return fmt.Errorf("unable to update DID document: %w", err)
	}

	// Resolve controllers of current version (could be the same document)
	didControllers, err := n.docResolver.ResolveControllers(*currentDIDDocument)
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
	signingTime := transaction.SigningTime()
	pKey, err := n.keyResolver.ResolvePublicKey(transaction.SigningKeyID(), &signingTime)
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
	sourceTransactions := append(missedTransactions, transaction.Ref())
	if len(missedTransactions) != 0 {
		mergedDoc, err := doc.MergeDocuments(*currentDIDDocument, proposedDIDDocument)
		if err != nil {
			return fmt.Errorf("unable to merge conflicted DID Document: %w", err)
		}
		proposedDIDDocument = *mergedDoc
	}

	updatedAt := transaction.SigningTime()
	documentMetadata := types.DocumentMetadata{
		Created:            currentDIDMeta.Created,
		Updated:            &updatedAt,
		Hash:               transaction.PayloadHash(),
		Deactivated:        store.IsDeactivated(proposedDIDDocument),
		SourceTransactions: sourceTransactions,
	}
	err = n.didStore.Update(proposedDIDDocument.ID, currentDIDMeta.Hash, proposedDIDDocument, &documentMetadata)
	if err == nil {
		logging.Log().Infof("DID document updated (tx=%s,did=%s)", transaction.Ref(), proposedDIDDocument.ID)
	}
	return err
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

	// Signing time should be set and lay in the past:
	if transaction.SigningTime().IsZero() || transaction.SigningTime().After(time.Now()) {
		return fmt.Errorf("signingTime must be set and in the past")
	}

	return nil
}

func (n ambassador) isUpdate(doc did.Document) (bool, error) {
	_, _, err := n.didStore.Resolve(doc.ID, nil)
	result := true

	if err == types.ErrNotFound {
		return false, nil
	}

	if err != nil {
		result = false
	}

	return result, err
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
