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
	"fmt"

	"github.com/nuts-foundation/nuts-node/vcr/verifier"

	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/log"
	"github.com/nuts-foundation/nuts-node/vcr/types"
)

// Ambassador registers a callback with the network for processing received Verifiable Credentials.
type Ambassador interface {
	// Configure instructs the ambassador to start receiving DID Documents from the network.
	Configure()
}

type ambassador struct {
	networkClient network.Transactions
	writer        Writer
	// verifier is used to store incoming revocations from the network
	verifier verifier.Verifier
}

// NewAmbassador creates a new listener for the network that listens to Verifiable Credential transactions.
func NewAmbassador(networkClient network.Transactions, writer Writer, verifier verifier.Verifier) Ambassador {
	return ambassador{
		networkClient: networkClient,
		writer:        writer,
		verifier:      verifier,
	}
}

// Configure instructs the ambassador to start receiving DID Documents from the network.
func (n ambassador) Configure() {
	n.networkClient.Subscribe(dag.TransactionPayloadAddedEvent, types.VcDocumentType, n.vcCallback)
	n.networkClient.Subscribe(dag.TransactionPayloadAddedEvent, types.RevocationLDDocumentType, n.jsonLDRevocationCallback)
}

// vcCallback gets called when new Verifiable Credentials are received by the network. All checks on the signature are already performed.
// The VCR is used to verify the contents of the credential.
// payload should be a json encoded vc.VerifiableCredential
func (n ambassador) vcCallback(tx dag.Transaction, payload []byte) error {
	log.Logger().Debugf("Processing VC received from Nuts Network (ref=%s)", tx.Ref())

	target := vc.VerifiableCredential{}
	if err := json.Unmarshal(payload, &target); err != nil {
		return fmt.Errorf("credential processing failed: %w", err)
	}

	// Verify and store
	validAt := tx.SigningTime()
	return n.writer.StoreCredential(target, &validAt)
}

// jsonLDRevocationCallback gets called when new credential revocations are received by the network.
// These revocations are in the form of a JSON-LD document.
// All checks on the signature are already performed.
// The VCR is used to verify the contents of the revocation.
// payload should be a json encoded Revocation
func (n ambassador) jsonLDRevocationCallback(tx dag.Transaction, payload []byte) error {
	log.Logger().Debugf("Processing VC revocation received from Nuts Network (ref=%s)", tx.Ref())

	r := credential.Revocation{}
	if err := json.Unmarshal(payload, &r); err != nil {
		return fmt.Errorf("revocation processing failed: %w", err)
	}

	return n.verifier.RegisterRevocation(r)
}
