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

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/nuts-foundation/go-did"

	crypto2 "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/vdr/types"

	"github.com/nuts-foundation/nuts-node/vdr/logging"
)

const DIDDocumentType = "application/json+did-document"

// Ambassador acts as integration point between VDR and network by sending DID Documents network and process
// DID Documents received through the network.
type Ambassador interface {
	// Start instructs the ambassador to start receiving DID Documents from the network.
	Start()
}

type ambassador struct {
	networkClient network.Network
	didStore      types.Store
	keyResolver   crypto2.KeyResolver
}

// NewAmbassador creates a new Ambassador,
func NewAmbassador(networkClient network.Network, didStore types.Store, keyResolver crypto2.KeyResolver) Ambassador {
	return &ambassador{
		networkClient: networkClient,
		didStore:      didStore,
		keyResolver:   keyResolver,
	}
}

// NewDocumentVersion contains the version number that a new Network Documents have.
const NewDocumentVersion = 0

// Start instructs the ambassador to start receiving DID Documents from the network.
func (n *ambassador) Start() {
	n.networkClient.Subscribe(DIDDocumentType, n.callback)
}

// thumbprintAlg is used for creating public key thumbprints
var thumbprintAlg = crypto.SHA256

// callback gets called when new DIDDocuments are received by the network. All checks on the signature are already performed.
// This method will check the integrity of the DID document related to the public key used to sign the network document.
// The rules are based on the Nuts RFC006
// payload should be a json encoded did.document
func (n *ambassador) callback(document dag.SubscriberDocument, payload []byte) error {
	logging.Log().Info("Processing DID documents received from Nuts Network.", DIDDocumentType, document.Ref())
	if err := checkSubscriberDocumentIntegrity(document); err != nil {
		return fmt.Errorf("callback could not process new DID Document: %w", err)
	}

	// Unmarshal the next/new proposed version of the DID Document
	var nextDIDDocument did.Document
	if err := json.Unmarshal(payload, &nextDIDDocument); err != nil {
		return fmt.Errorf("unable to unmarshall did document from network payload: %w", err)
	}

	if isUpdate(document) {
		return n.updateDIDDocument(document, nextDIDDocument)
	}
	return n.createDIDDocument(document, nextDIDDocument)
}

func (n *ambassador) createDIDDocument(document dag.SubscriberDocument, nextDIDDocument did.Document) error {
	// First, check if the network document was signed by the same key as is embedded in the DID Document`s authenticationMethod:

	// Take signing key from network document header
	headerKey := document.SigningKey()
	// Create key thumbprint
	headerKeyThumbprint, err := headerKey.Thumbprint(thumbprintAlg)
	if err != nil {
		return fmt.Errorf("unable to generate network document signing key thumbprint: %w", err)
	}

	// Check if headerKey is one of the keys embedded in the authenticationMethod
	didDocumentAuthKeys := nextDIDDocument.Authentication
	if documentKey, err := n.findKeyByThumbprint(headerKeyThumbprint, didDocumentAuthKeys); documentKey == nil || err != nil {
		if documentKey == nil {
			return fmt.Errorf("key used to sign Network document must be be part of DID Document authentication")
		}
		return err
	}

	documentMetadata := types.DocumentMetadata{
		Created:    document.SigningTime(),
		Updated:    nil,
		Version:    NewDocumentVersion,
		TimelineID: document.Ref(),
		Hash:       document.PayloadHash(),
	}
	return n.didStore.Write(nextDIDDocument, documentMetadata)
}

func (n *ambassador) updateDIDDocument(document dag.SubscriberDocument, nextDIDDocument did.Document) error {
	// Resolve current version of DID Document
	resolverMetadata := &types.ResolveMetadata{
		AllowDeactivated: false,
	}
	currentDIDDocument, currentDIDMeta, err := n.didStore.Resolve(nextDIDDocument.ID, resolverMetadata)
	if err != nil {
		return fmt.Errorf("unable to update did document: %s", err)
	}
	// Check if the new document is actual newer by comparing timeline versions
	if currentDIDMeta.Version >= document.TimelineVersion() {
		return fmt.Errorf("unable to update did document: timeline version of current document is greater or equal to the new version")
	}
	if currentDIDMeta.TimelineID != document.TimelineID() {
		return fmt.Errorf("timelineIDs of new and current DID documents must match")
	}

	// Resolve controllers of current version (could be the same document)
	didControllers, err := n.resolveDIDControllers(currentDIDDocument)
	logging.Log().Debug(didControllers)

	var controllerVerificationRelationships = []did.VerificationRelationship{}
	for _, didCtrl := range didControllers {
		for _, auth := range didCtrl.Authentication {
			controllerVerificationRelationships = append(controllerVerificationRelationships, auth)
		}
	}

	// In an update, only the keyID is provided in te network document. Resolve the key from the key store
	pKey, err := n.keyResolver.GetPublicKey(document.SigningKeyID(), document.SigningTime())
	if err != nil {
		return fmt.Errorf("unable to resolve signingkey %w", err)
	}
	headerKey, err := jwk.New(pKey)
	if err != nil {
		return fmt.Errorf("could not parse public key into jwk %w", err)
	}

	// Create thumbprint
	headerKeyThumbprint, err := headerKey.Thumbprint(thumbprintAlg)
	if err != nil {
		return fmt.Errorf("unable to generate network document signing key thumbprint")
	}
	// Check if the signingKey is listed as a valid authenticationMethod in one of the controllers
	keyToSign, err := n.findKeyByThumbprint(headerKeyThumbprint, controllerVerificationRelationships)
	if keyToSign == nil {
		return fmt.Errorf("network document not signed by one of its controllers")
	}

	// TODO: perform all these tests:
	// Take authenticationMethod keys from the controllers
	// Check if network header keyID is one of authenticationMethods of the controller
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
		Created:    currentDIDMeta.Created,
		Updated:    &updatedAt,
		Version:    document.TimelineVersion(),
		TimelineID: document.TimelineID(),
		Hash:       document.PayloadHash(),
	}
	return n.didStore.Update(nextDIDDocument.ID, currentDIDMeta.Hash, nextDIDDocument, &documentMetadata)
}

// checkSubscriberDocumentIntegrity performs basic integrity checks on the SubscriberDocument fields:
func checkSubscriberDocumentIntegrity(document dag.SubscriberDocument) error {
	// check the payload type:
	if document.PayloadType() != DIDDocumentType {
		return fmt.Errorf("wrong payload type for this subscriber. Can handle: %s, got: %s", DIDDocumentType, document.PayloadType())
	}

	// PayloadHash must be set
	if document.PayloadHash().Empty() {
		return fmt.Errorf("payloadHash must be provider")
	}

	// Signing time should be set and lay in the past:
	// allow for 2 seconds clock skew
	if document.SigningTime().IsZero() || document.SigningTime().After(time.Now().Add(2*time.Second)) {
		return fmt.Errorf("signingTime must be set and in the past")
	}

	if isUpdate(document) {
		// For a DID Document update TimelineID must be set
		if document.TimelineID().Empty() {
			return fmt.Errorf("timelineID must be set for updates")
		}

		if document.TimelineVersion() <= NewDocumentVersion {
			return fmt.Errorf("timelineVersion for updates must be greater than %d", NewDocumentVersion)
		}
	} else {
		// For a new DID Document TimelineID must be nil
		if !document.TimelineID().Empty() {
			return fmt.Errorf("timelineID for new documents must be absent")
		}

		if document.TimelineVersion() != NewDocumentVersion {
			return fmt.Errorf("timelineVersion for new documents must be absent or equal to %d", NewDocumentVersion)
		}

		// For new DID Documents the signing key must be embedded in the network document
		if document.SigningKey() == nil {
			return fmt.Errorf("signingKey for new DID Documents must be set")
		}
	}

	return nil
}

func isUpdate(document dag.SubscriberDocument) bool {
	return !document.TimelineID().Empty()
}

// resolveDIDControllers tries to resolve the controllers for a given DID Document
// If no controllers are present, the current version of the document will be resolved
// If a controller could not be found, it will return an error
func (n ambassador) resolveDIDControllers(didDocument *did.Document) ([]*did.Document, error) {
	var didControllers = []*did.Document{}
	docsToResolve := didDocument.Controller
	if len(docsToResolve) == 0 {
		docsToResolve = append(docsToResolve, didDocument.ID)
	}

	for _, ctrlDID := range docsToResolve {
		controllerDoc, _, err := n.didStore.Resolve(ctrlDID, &types.ResolveMetadata{})
		if err != nil {
			return nil, fmt.Errorf("unable to resolve document controller: %w", err)
		}
		didControllers = append(didControllers, controllerDoc)
	}
	return didControllers, nil
}

// findKeyByThumbprint accepts a SHA256 generated thumbprint and tries to find it in a provided list of did.VerificationRelationship s.
// Returns an error if it could not generate a thumbprint of one of the VerificationRelationship keys
func (n ambassador) findKeyByThumbprint(thumbPrint []byte, didDocumentAuthKeys []did.VerificationRelationship) (jwk.Key, error) {
	hashAlg := crypto.SHA256

	var documentKey jwk.Key
	for _, key := range didDocumentAuthKeys {
		// Create thumbprint
		documentThumbprint, err := key.JWK().Thumbprint(hashAlg)
		if err != nil {
			return nil, fmt.Errorf("unable to generate did document signing key thumbprint")
		}
		// Compare thumbprints
		if bytes.Equal(thumbPrint, documentThumbprint) {
			documentKey = key.JWK()
			break
		}
	}
	return documentKey, nil
}
