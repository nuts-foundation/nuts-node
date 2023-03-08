/*
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
	"context"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/network/transport"
)

// MaxReprocessBufferSize is the maximum number of events for Nats resulting from a Reprocess
const MaxReprocessBufferSize = 1000000

// Transactions is the interface that defines the API for creating, reading and subscribing to Nuts Network transactions.
type Transactions interface {
	// Subscribe registers a receiver for the specified transaction type.
	// A filter can be passed as option with the WithSelectionFilter function.
	// The events for the receiver can be made persistent by passing the network.WithPersistency() option.
	Subscribe(name string, receiver dag.ReceiverFn, filters ...SubscriberOption) error
	// Subscribers returns the list of notifiers on the DAG that emit events to subscribers.
	Subscribers() []dag.Notifier
	// CleanupSubscriberEvents removes events. Example use is cleaning up events that errored but should be removed due to a bugfix.
	CleanupSubscriberEvents(subcriberName, errorPrefix string) error
	// GetTransactionPayload retrieves the transaction Payload for the given transaction.
	// If the transaction or Payload is not found, dag.ErrPayloadNotFound is returned.
	GetTransactionPayload(transactionRef hash.SHA256Hash) ([]byte, error)
	// GetTransaction retrieves the transaction for the given reference.
	// If the transaction is not found, a dag.ErrTransactionNotFound is returned.
	GetTransaction(transactionRef hash.SHA256Hash) (dag.Transaction, error)
	// CreateTransaction creates a new transaction according to the given spec.
	CreateTransaction(ctx context.Context, spec Template) (dag.Transaction, error)
	// ListTransactionsInRange returns all transactions known to this Network instance with lamport clock value between startInclusive and endExclusive.
	// endExclusive must be larger than startInclusive.
	ListTransactionsInRange(startInclusive uint32, endExclusive uint32) ([]dag.Transaction, error)
	// PeerDiagnostics returns a map containing diagnostic information of the node's peers. The key contains the remote peer's ID.
	PeerDiagnostics() map[transport.PeerID]transport.Diagnostics
	// Reprocess walks the DAG and publishes all transactions matching the contentType via Nats
	Reprocess(ctx context.Context, contentType string) (*ReprocessReport, error)
	// WithPersistency returns a SubscriberOption for persistency. It allows the DAG KVStore to be used as persistent store for notifications.
	// The notifications will then have ACID properties
	WithPersistency() SubscriberOption
	// DiscoverServices should be called by the VDR to let the network know it has processed and verified a document (update) for the DID.
	DiscoverServices(updatedDID did.DID)

	DiagnosticsProviders() map[string]core.DiagnosticsProvider
}

// EventType defines a type for specifying the kind of events that can be published/subscribed on the Network.
type EventType string

// AnyPayloadType is a wildcard that matches with any payload type.
const AnyPayloadType = "*"

// Receiver defines a callback function for processing transactions/payloads received by the DAG.
type Receiver func(transaction dag.Transaction, payload []byte) error

// SubscriberOption creates a dag.NotifierOption
type SubscriberOption func() dag.NotifierOption
