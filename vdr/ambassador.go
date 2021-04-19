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
	"fmt"
	"time"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/vdr/doc"
	"github.com/nuts-foundation/nuts-node/vdr/store"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/vdr/logging"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

// didDocumentType contains network transaction mime-type to identify a DID Document in the network.
const didDocumentType = "application/did+json"

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

// newDocumentVersion contains the version number that a new Network Documents have.
const newDocumentVersion = 0

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
func (n *ambassador) callback(tx dag.SubscriberTransaction, payload []byte) error {
	logging.Log().Debugf("Processing DID document received from Nuts Network (ref=%s)", tx.Ref())
	if err := checkSubscriberTransactionIntegrity(tx); err != nil {
		return fmt.Errorf("callback could not process new DID Document: %w", err)
	}

	// Unmarshal the next/new proposed version of the DID Document
	var nextDIDDocument did.Document
	if err := json.Unmarshal(payload, &nextDIDDocument); err != nil {
		return fmt.Errorf("unable to unmarshall did document from network payload: %w", err)
	}

	if err := checkDIDDocumentIntegrity(nextDIDDocument); err != nil {
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

func (n *ambassador) handleCreateDIDDocument(transaction dag.SubscriberTransaction, proposedDIDDocument did.Document) error {
	// Check if the transaction was signed by the same key as is embedded in the DID Document`s authenticationMethod:
	if transaction.SigningKey() == nil {
		return fmt.Errorf("callback could not process new DID Document: signingKey for new DID Documents must be set")
	}

	// Create key thumbprint from the transactions signingKey embedded in the header
	signingKeyThumbprint, err := transaction.SigningKey().Thumbprint(thumbprintAlg)
	if err != nil {
		return fmt.Errorf("unable to generate network transaction signing key thumbprint: %w", err)
	}

	// Check if signingKey is one of the keys embedded in the CapabilityInvocation
	didDocumentAuthKeys := proposedDIDDocument.CapabilityInvocation
	if documentKey, err := n.findKeyByThumbprint(signingKeyThumbprint, didDocumentAuthKeys); documentKey == nil || err != nil {
		if err != nil {
			return err
		}
		return fmt.Errorf("key used to sign transaction must be be part of DID Document authentication")
	}

	var rawKey crypto.PublicKey
	err = transaction.SigningKey().Raw(&rawKey)
	if err != nil {
		return err
	}

	documentMetadata := types.DocumentMetadata{
		Created: transaction.SigningTime(),
		Hash:    transaction.PayloadHash(),
	}
	return n.didStore.Write(proposedDIDDocument, documentMetadata)
}

func (n *ambassador) handleUpdateDIDDocument(document dag.SubscriberTransaction, proposedDIDDocument did.Document) error {
	// Resolve latest version of DID Document
	currentDIDDocument, currentDIDMeta, err := n.didStore.Resolve(proposedDIDDocument.ID, nil)
	if err != nil {
		return fmt.Errorf("unable to update did document: %w", err)
	}

	// Resolve controllers of current version (could be the same document)
	didControllers, err := n.docResolver.ResolveControllers(*currentDIDDocument)

	var controllerVerificationRelationships []did.VerificationRelationship
	for _, didCtrl := range didControllers {
		for _, capInv := range didCtrl.CapabilityInvocation {
			controllerVerificationRelationships = append(controllerVerificationRelationships, capInv)
		}
	}

	// In an update, only the keyID is provided in the network document. Resolve the key from the key store
	// This should succeed since the signature of the network document has already been verified.
	signingTime := document.SigningTime()
	pKey, err := n.keyResolver.ResolvePublicKey(document.SigningKeyID(), &signingTime)
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

	// Check if the signingKey is listed as a valid authenticationMethod in one of the controllers
	keyToSign, err := n.findKeyByThumbprint(signingKeyThumbprint, controllerVerificationRelationships)
	if err != nil {
		return fmt.Errorf("unable to find signingKey by thumprint in controllers: %w", err)
	}
	if keyToSign == nil {
		return fmt.Errorf("network document not signed by one of its controllers")
	}

	// TODO: perform all these tests:
	// Take authenticationMethod keys from the controllers
	// Check if network signingKeyID is one of authenticationMethods of the controller
	//
	// For each verificationMethod in the next version document
	// 		check if the provided key thumbprint matches the corresponding thumbprint in the key store
	// Take diff of verificationMethods between next and current versions:
	// if new verificationMethod is added:
	// 		Add public key to key store
	// if verificationMethod is removed:
	//		Mark keyID as expired since the updatedAt time from new DID document

	// make a diff of the controllers
	// 	if controller is added
	//		check if it is known.
	updatedAt := document.SigningTime()
	documentMetadata := types.DocumentMetadata{
		Created:     currentDIDMeta.Created,
		Updated:     &updatedAt,
		Hash:        document.PayloadHash(),
		Deactivated: store.IsDeactivated(proposedDIDDocument),
	}
	return n.didStore.Update(proposedDIDDocument.ID, currentDIDMeta.Hash, proposedDIDDocument, &documentMetadata)
}

// checkSubscriberTransactionIntegrity performs basic integrity checks on the SubscriberTransaction fields
// Some checks may look redundant because they are performed in the callers, this method has the sole
// responsibility to ensure integrity, while the other may have not.
func checkSubscriberTransactionIntegrity(transaction dag.SubscriberTransaction) error {
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

// checkDIDDocumentIntegrity checks for inconsistencies in the the DID Document:
// - validate it according to the W3C DID Core Data Model specification
// - validate is according to the Nuts DID Method specification:
//  - it checks validationMethods for the following conditions:
//   - every validationMethod id must have a fragment
//   - every validationMethod id should have the DID prefix
//   - every validationMethod id must be unique
//  - it checks services for the following conditions:
//   - every service id must have a fragment
//   - every service id should have the DID prefix
//   - every service id must be unique
func checkDIDDocumentIntegrity(doc did.Document) error {
	if err := (did.W3CSpecValidator{}).Validate(doc); err != nil {
		return err
	}

	// Verification methods
	knownKeyIds := make(map[string]bool, 0)
	for _, method := range doc.VerificationMethod {
		if err := verifyDocumentEntryID(doc.ID, method.ID.URI(), knownKeyIds); err != nil {
			return fmt.Errorf("invalid verificationMethod: %w", err)
		}
	}
	// Services
	knownServiceIDs := make(map[string]bool, 0)
	for _, method := range doc.Service {
		if err := verifyDocumentEntryID(doc.ID, method.ID, knownServiceIDs); err != nil {
			return fmt.Errorf("invalid service: %w", err)
		}
	}
	return nil
}

func verifyDocumentEntryID(owner did.DID, entryID ssi.URI, knownIDs map[string]bool) error {
	// Check theID has a fragment
	if len(entryID.Fragment) == 0 {
		return fmt.Errorf("ID must have a fragment")
	}
	// Check if this ID was part of a previous entry
	entryIDStr := entryID.String()
	if knownIDs[entryIDStr] {
		return fmt.Errorf("ID must be unique")
	}
	entryIDAsDID, err := did.ParseDID(entryIDStr)
	if err != nil {
		// Shouldn't happen
		return err
	}
	entryIDAsDID.Fragment = ""
	if !owner.Equals(*entryIDAsDID) {
		return fmt.Errorf("ID must have document prefix")
	}
	knownIDs[entryIDStr] = true
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
			return nil, fmt.Errorf("unable to generate did document signing key thumbprint: %w", err)
		}
		// Compare thumbprints
		if bytes.Equal(thumbPrint, documentThumbprint) {
			documentKey = keyAsJWK
			break
		}
	}
	return documentKey, nil
}
