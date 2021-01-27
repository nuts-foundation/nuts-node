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
	storeWriter   types.DocWriter
	keyResolver   crypto2.KeyResolver
}

// NewAmbassador creates a new Ambassador,
func NewAmbassador(networkClient network.Network, storeWriter types.DocWriter, keyResolver crypto2.KeyResolver) Ambassador {
	return &ambassador{
		networkClient: networkClient,
		storeWriter:   storeWriter,
		keyResolver:   keyResolver,
	}
}

// NewDocumentVersion contains the version number that a new Network Documents have.
const NewDocumentVersion = 0

// Start instructs the ambassador to start receiving DID Documents from the network.
func (n *ambassador) Start() {
	n.networkClient.Subscribe(DIDDocumentType, func(document dag.Document, payload []byte) error {
		logging.Log().Warn("Processing DID documents received from Nuts Network.", DIDDocumentType, document.Ref())

		var didDocument did.Document
		if err := json.Unmarshal(payload, &didDocument); err != nil {
			return err
		}


		if document.TimelineVersion() == NewDocumentVersion {
			// Create:
			// -------
			// Take key from network document header
			// Check if keyID in network document header is the same as the keyID in the authenticationMethod
			// Check if the thumbprints from the network header key and the authenticationMethod are the same

			hashAlg := crypto.SHA256

			// Find header key
			headerKey := document.SigningKey()
			// Create thumbprint
			headerKeyThumbprint, err := headerKey.Thumbprint(hashAlg)
			if err != nil {
				return fmt.Errorf("unable to generate network document signing key thumbprint")
			}

			// Find authentication method by keyID
			didDocumentAuthKeys := didDocument.Authentication
			var documentKey jwk.Key
			for _, key := range didDocumentAuthKeys {
				// Create thumbprint
				documentThumbprint, err := key.JWK().Thumbprint(hashAlg)
				if err != nil {
					return fmt.Errorf("unable to generate did document signing key thumbprint")
				}
				// Compare thumbprints
				if bytes.Equal(headerKeyThumbprint, documentThumbprint) {
					documentKey = key.JWK()
					break
				}
			}
			if documentKey == nil {
				return fmt.Errorf("key used to sign Network document must be be part DID Document authentication")
			}

			documentMetadata := types.DocumentMetadata{
				Created:       document.SigningTime(),
				Updated:       nil,
				Version:       0,
				OriginJWSHash: document.Ref(),
				Hash:          document.Payload(),
			}
			return n.storeWriter.Write(didDocument, documentMetadata)
		} else { // updated document
			// Update:
			// -------
			// Resolve current version of DID Document
			// Resolve controller of current version (could be the same document)
			// Take authenticationMethod keys from the controller
			// Check if keyID is part of authenticationMethods of the controller
			//
			// For each verificationMethod in the next version document
			// 		check if the provided key thumbprint matches the corresponding thumbprint in the key store
			// Take diff of verificationMethods between next and current versions:
			// if new verificationMethod is added:
			// 		Add public key to key store
			// if verificationMethod is removed:
			//		Mark keyID as expired since the updatedAt time from new DID document
			logging.Log().Warn("Not implemented: updating a DID document")
		}
		return nil
	})
}
