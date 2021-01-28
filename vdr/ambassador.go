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
	n.networkClient.Subscribe(DIDDocumentType, func(document dag.Document, payload []byte) error {
		logging.Log().Info("Processing DID documents received from Nuts Network.", DIDDocumentType, document.Ref())

		// Unmarshal the next proposed version of the DID Document
		var nextDIDDocument did.Document
		if err := json.Unmarshal(payload, &nextDIDDocument); err != nil {
			return err
		}

		hashAlg := crypto.SHA256

		// Create:
		// -------
		if document.TimelineVersion() == NewDocumentVersion {
			// Take key from network document header
			// Check if the key used to sign the network document is embedded in the DID Documents authenticationMethod
			// 	by comparing both keys thumbprints


			// Find header key which for new did documents is provided
			headerKey := document.SigningKey()
			// Create thumbprint
			headerKeyThumbprint, err := headerKey.Thumbprint(hashAlg)
			if err != nil {
				return fmt.Errorf("unable to generate network document signing key thumbprint")
			}

			// Check if key is part oth authenticationMethod
			didDocumentAuthKeys := nextDIDDocument.Authentication
			if documentKey, err := n.findKeyByThumbprint(headerKeyThumbprint, didDocumentAuthKeys); documentKey == nil || err != nil {
				if documentKey == nil {
					return fmt.Errorf("key used to sign Network document must be be part DID Document authentication")
				}
				return err
			}

			documentMetadata := types.DocumentMetadata{
				Created:       document.SigningTime(),
				Updated:       nil,
				Version:       NewDocumentVersion,
				OriginJWSHash: document.Ref(),
				Hash:          document.Payload(),
			}
			return n.didStore.Write(nextDIDDocument, documentMetadata)
		} else { // updated document
			// Update:
			// -------
			// Resolve current version of DID Document
			ref := document.Ref()
			resolverMetadata := &types.ResolveMetadata{
				Hash:             &ref,
				AllowDeactivated: false,
			}
			currentDIDDocument, _, err := n.didStore.Resolve(nextDIDDocument.ID, resolverMetadata)
			if err != nil {
				return fmt.Errorf("unable to update did document: %s", err)
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

			// in an update, the only the keyID is provided in te network document. Resolve it from the key store
			pKey, err := n.keyResolver.GetPublicKey(document.SigningKeyID(), document.SigningTime())
			if err != nil {
				return fmt.Errorf("unable to resolve signingkey %w", err)
			}
			headerKey, err := jwk.New(pKey)
			if err != nil {
				return fmt.Errorf("could not parse public key into jwk %w", err)
			}

			// Create thumbprint
			headerKeyThumbprint, err := headerKey.Thumbprint(hashAlg)
			if err != nil {
				return fmt.Errorf("unable to generate network document signing key thumbprint")
			}
			keyToSign, err := n.findKeyByThumbprint(headerKeyThumbprint, controllerVerificationRelationships)
			if keyToSign == nil {
				return fmt.Errorf("network document not signed by one of its controllers")
			}

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
			logging.Log().Warn("Not implemented: updating a DID document")
		}
		return nil
	})
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
		controllerDoc, _, err := n.didStore.Resolve(ctrlDID, nil)
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