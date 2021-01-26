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
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/nuts-foundation/nuts-node/network/dag"

	"github.com/nuts-foundation/nuts-node/vdr/logging"
)

const documentType = "nuts.registry-event"

// Ambassador acts as integration point between VDR and network by sending DID Documents network and process
// DID Documents received through the network.
type Ambassador interface {
	// Start instructs the ambassador to start receiving DID Documents from the network.
	Start()
}

type ambassador struct {
	networkClient network.Network
}

// NewAmbassador creates a new Ambassador,
func NewAmbassador(networkClient network.Network) Ambassador {
	instance := &ambassador{
		networkClient: networkClient,
	}
	return instance
}

// Start instructs the ambassador to start receiving DID Documents from the network.
func (n *ambassador) Start() {
	n.networkClient.Subscribe(documentType, func(document dag.Document, payload []byte) error {
		logging.Log().Warn("Not implemented: processing DID documents received from Nuts Network.")
		return nil
	})
}
