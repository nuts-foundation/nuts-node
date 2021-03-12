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

package vcr

import (
	"encoding/json"

	"github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vdr/logging"
	"github.com/pkg/errors"
)

// Ambassador registers a vcCallback with the network for processing received Verifiable Credentials.
type Ambassador interface {
	// Configure instructs the ambassador to start receiving DID Documents from the network.
	Configure()
}

type ambassador struct {
	networkClient network.Transactions
	writer        Writer
}

// NewAmbassador creates a new listener for the network that listens to Verifiable Credential transactions.
func NewAmbassador(networkClient network.Transactions, writer Writer) Ambassador {
	return ambassador{
		networkClient: networkClient,
		writer:        writer,
	}
}

// Configure instructs the ambassador to start receiving DID Documents from the network.
func (n ambassador) Configure() {
	n.networkClient.Subscribe(vcDocumentType, n.vcCallback)
	n.networkClient.Subscribe(revocationDocumentType, n.rCallback)
}

// vcCallback gets called when new Verifiable Credentials are received by the network. All checks on the signature are already performed.
// The VCR is used to verify the contents of the credential.
// payload should be a json encoded did.VerifiableCredential
func (n ambassador) vcCallback(tx dag.SubscriberTransaction, payload []byte) error {
	logging.Log().Debugf("Processing Verifiable Credential received from Nuts Network: ref=%s", tx.Ref())

	vc := did.VerifiableCredential{}
	if err := json.Unmarshal(payload, &vc); err != nil {
		return errors.Wrap(err, "credential processing failed")
	}

	// Verify and store
	return n.writer.StoreCredential(vc)
}

// rCallback gets called when new credential revocations are received by the network. All checks on the signature are already performed.
// The VCR is used to verify the contents of the revocation.
// payload should be a json encoded Revocation
func (n ambassador) rCallback(tx dag.SubscriberTransaction, payload []byte) error {
	logging.Log().Debugf("Processing Credential revocation received from Nuts Network: ref=%s", tx.Ref())

	r := credential.Revocation{}
	if err := json.Unmarshal(payload, &r); err != nil {
		return errors.Wrap(err, "revocation processing failed")
	}

	// Verify and store
	return n.writer.StoreRevocation(r)
}
