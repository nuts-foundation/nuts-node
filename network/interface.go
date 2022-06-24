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
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/network/transport"
)

// MaxReprocessBufferSize is the maximum number of events for Nats resulting from a Reprocess
const MaxReprocessBufferSize = 1000000

// Transactions is the interface that defines the API for creating, reading and subscribing to Nuts Network transactions.
type Transactions interface {
	// Subscribe register a receiver for the specified transaction type. The receiver is called when a transaction
	// matches with the given dag.NotificationFilter's.
	Subscribe(name string, receiver dag.ReceiverFn, filters ...dag.NotifierOption) error
	// GetTransactionPayload retrieves the transaction Payload for the given transaction. If the transaction or Payload is not found
	// nil is returned.
	GetTransactionPayload(transactionRef hash.SHA256Hash) ([]byte, error)
	// GetTransaction retrieves the transaction for the given reference. If the transaction is not known, an error is returned.
	GetTransaction(transactionRef hash.SHA256Hash) (dag.Transaction, error)
	// CreateTransaction creates a new transaction according to the given spec.
	CreateTransaction(spec Template) (dag.Transaction, error)
	// ListTransactionsInRange returns all transactions known to this Network instance with lamport clock value between startInclusive and endExclusive.
	// endExclusive must be larger than startInclusive.
	ListTransactionsInRange(startInclusive uint32, endExclusive uint32) ([]dag.Transaction, error)
	// Walk walks the DAG starting at the root, calling `visitor` for every transaction.
	Walk(visitor dag.Visitor) error
	// PeerDiagnostics returns a map containing diagnostic information of the node's peers. The key contains the remote peer's ID.
	PeerDiagnostics() map[transport.PeerID]transport.Diagnostics
	// Reprocess walks the DAG and publishes all transactions matching the contentType via Nats
	// This is an async process and will not return any feedback
	Reprocess(contentType string)
}

// EventType defines a type for specifying the kind of events that can be published/subscribed on the Network.
type EventType string

const (
	// TransactionAddedEvent is called when a transaction is added to the DAG. Its payload may not be present.
	TransactionAddedEvent EventType = "TRANSACTION_ADDED"
	// TransactionPayloadAddedEvent is called when a transaction is added to the DAG including its payload.
	TransactionPayloadAddedEvent EventType = "TRANSACTION_PAYLOAD_ADDED"
)

// AnyPayloadType is a wildcard that matches with any payload type.
const AnyPayloadType = "*"

// Receiver defines a callback function for processing transactions/payloads received by the DAG.
type Receiver func(transaction dag.Transaction, payload []byte) error
