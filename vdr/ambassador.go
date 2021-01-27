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
	"encoding/json"

	"github.com/nuts-foundation/go-did"

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
}

// NewAmbassador creates a new Ambassador,
func NewAmbassador(networkClient network.Network, storeWriter types.DocWriter) Ambassador {
	return &ambassador{
		networkClient: networkClient,
		storeWriter:   storeWriter,
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



		// New Document or updated?
		if document.TimelineVersion() == NewDocumentVersion {
			documentMetadata := types.DocumentMetadata{
				Created:       document.SigningTime(),
				Updated:       nil,
				Version:       0,
				OriginJWSHash: document.Ref(),
				Hash:          document.Payload(),
			}
			// TODO: perform all checks:
			// * TODO: make up a list of checks ;)
			return n.storeWriter.Write(didDocument, documentMetadata)
		} else { // updated document
			logging.Log().Warn("Not implemented: updating a DID document")
		}
		return nil
	})
}
