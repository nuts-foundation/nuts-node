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

package network

import (
	"bytes"

	network "github.com/nuts-foundation/nuts-network/pkg"
	"github.com/nuts-foundation/nuts-network/pkg/model"

	"github.com/nuts-foundation/nuts-node/vdr/logging"
)

const documentType = "nuts.registry-event"

// Ambassador acts as integration point between the registry and network by sending registry events to the
// network and (later on) process notifications of new documents on the network that might be of interest to the registry.
type Ambassador interface {
	// Start instructs the ambassador to start receiving events from the network.
	Start()
}

type ambassador struct {
	networkClient network.NetworkClient
}

// NewAmbassador creates a new Ambassador. Don't forget to call RegisterEventHandlers afterwards.
func NewAmbassador(networkClient network.NetworkClient) Ambassador {
	instance := &ambassador{
		networkClient: networkClient,
	}
	return instance
}

// Start instructs the ambassador to start receiving events from the network.
func (n *ambassador) Start() {
	queue := n.networkClient.Subscribe(documentType)
	go func() {
		for {
			document := queue.Get()
			if document == nil {
				return
			}
			n.processDocument(document)
		}
	}()
}

func (n *ambassador) sendEventToNetwork() {
	logging.Log().Infof("Event published on network")
}

func (n *ambassador) processDocument(document *model.Document) {
	logging.Log().Infof("Received event through Nuts Network: %s", document.Hash)
	reader, err := n.networkClient.GetDocumentContents(document.Hash)
	if err != nil {
		logging.Log().Errorf("Unable to retrieve document from Nuts Network (hash=%s): %v", document.Hash, err)
		return
	}
	buf := new(bytes.Buffer)
	if _, err = buf.ReadFrom(reader); err != nil {
		logging.Log().Errorf("Unable read document data from Nuts Network (hash=%s): %v", document.Hash, err)
		return
	}
	// todo process
}
