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
	"context"
	"encoding/json"
	"fmt"
	"github.com/nats-io/nats.go"
	"github.com/nuts-foundation/nuts-node/events"
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
	Configure() error
	// Start the event subscriber for reprocessing transactions from the DAG when called
	Start() error
}

type ambassador struct {
	networkClient network.Transactions
	writer        Writer
	// verifier is used to store incoming revocations from the network
	verifier     verifier.Verifier
	eventManager events.Event
}

// NewAmbassador creates a new listener for the network that listens to Verifiable Credential transactions.
func NewAmbassador(networkClient network.Transactions, writer Writer, verifier verifier.Verifier, eventManager events.Event) Ambassador {
	return &ambassador{
		networkClient: networkClient,
		writer:        writer,
		verifier:      verifier,
		eventManager:  eventManager,
	}
}

// Configure instructs the ambassador to start receiving DID Documents from the network.
func (n ambassador) Configure() error {
	err := n.networkClient.Subscribe("vcr_vcs", n.handleNetworkVCs,
		n.networkClient.WithPersistency(),
		network.WithSelectionFilter(func(event dag.Event) bool {
			return event.Type == dag.PayloadEventType && event.Transaction.PayloadType() == types.VcDocumentType
		}))
	if err != nil {
		return err
	}
	return n.networkClient.Subscribe("vcr_revocations", n.handleNetworkRevocations,
		n.networkClient.WithPersistency(),
		network.WithSelectionFilter(func(event dag.Event) bool {
			return event.Type == dag.PayloadEventType && event.Transaction.PayloadType() == types.RevocationLDDocumentType
		}))
}

func (n ambassador) Start() error {
	stream := events.NewDisposableStream(
		fmt.Sprintf("%s_%s", events.ReprocessStream, "VCR"),
		[]string{
			fmt.Sprintf("%s.%s", events.ReprocessStream, types.VcDocumentType),
			fmt.Sprintf("%s.%s", events.ReprocessStream, types.RevocationLDDocumentType),
		},
		network.MaxReprocessBufferSize)
	conn, _, err := n.eventManager.Pool().Acquire(context.Background())
	if err != nil {
		return fmt.Errorf("failed to subscribe to REPROCESS event stream: %v", err)
	}

	err = stream.Subscribe(conn, "VCR", fmt.Sprintf("%s.*", events.ReprocessStream), n.handleReprocessEvent)
	if err != nil {
		return fmt.Errorf("failed to subscribe to REPROCESS event stream: %v", err)
	}
	return nil
}

func (n *ambassador) handleNetworkVCs(event dag.Event) (bool, error) {
	if err := n.vcCallback(event.Transaction, event.Payload); err != nil {
		return false, err
	}
	return true, nil
}

func (n *ambassador) handleNetworkRevocations(event dag.Event) (bool, error) {
	if err := n.jsonLDRevocationCallback(event.Transaction, event.Payload); err != nil {
		return false, err
	}
	return true, nil
}

func (n ambassador) handleReprocessEvent(msg *nats.Msg) {
	jsonBytes := msg.Data
	twp := events.TransactionWithPayload{}

	if err := msg.Ack(); err != nil {
		log.Logger().
			WithError(err).
			WithField("evenSubject", msg.Subject).
			Error("Failed to process event: failed to ack message")
		return
	}

	if err := json.Unmarshal(jsonBytes, &twp); err != nil {
		log.Logger().
			WithError(err).
			WithField("evenSubject", msg.Subject).
			Error("Failed to process event: failed to unmarshall data")
		return
	}

	if len(twp.Payload) != 0 { // private TXs not intended for us
		callback := n.getCallbackFn(twp.Transaction.PayloadType())
		if err := callback(twp.Transaction, twp.Payload); err != nil {
			log.Logger().
				WithError(err).
				WithField("evenSubject", msg.Subject).
				Error("Failed to process event")
			return
		}
	}

	return
}

func (n ambassador) getCallbackFn(contentType string) func(dag.Transaction, []byte) error {
	switch contentType {
	case types.VcDocumentType:
		return n.vcCallback
	case types.RevocationLDDocumentType:
		return n.jsonLDRevocationCallback
	}

	return func(tx dag.Transaction, payload []byte) error {
		return nil
	}
}

// vcCallback gets called when new Verifiable Credentials are received by the network. All checks on the signature are already performed.
// The VCR is used to verify the contents of the credential.
// payload should be a json encoded vc.VerifiableCredential
func (n ambassador) vcCallback(tx dag.Transaction, payload []byte) error {
	log.Logger().
		WithField("txRef", tx.Ref()).
		Debug("Processing VC received from Nuts Network")

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
	log.Logger().
		WithField("txRef", tx.Ref()).
		Debug("Processing VC revocation received from Nuts Network")

	r := credential.Revocation{}
	if err := json.Unmarshal(payload, &r); err != nil {
		return fmt.Errorf("revocation processing failed: %w", err)
	}

	return n.verifier.RegisterRevocation(r)
}
