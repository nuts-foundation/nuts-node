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

package dag

import (
	"context"
	"errors"
	"time"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag/tree"
)

// AnyPayloadType is a wildcard that matches with any payload type.
const AnyPayloadType = "*"

var errRootAlreadyExists = errors.New("root transaction already exists")
var errNoClockValue = errors.New("missing clock value")

// State represents the Node transactional state. Mutations are done via this abstraction layer.
// Notifications are also done via this layer
type State interface {
	// PayloadStore interface for wrapping payloadStore behind TX
	PayloadStore
	core.Diagnosable

	// Add a transactions to the DAG. If it can't be added an error is returned.
	// The payload may be passed as well. Allowing for better notification of observers
	Add(ctx context.Context, transactions Transaction, payload []byte) error
	// FindBetween finds all transactions which signing time lies between startInclude and endExclusive.
	// It returns the transactions in DAG walking order.
	FindBetween(ctx context.Context, startInclusive time.Time, endExclusive time.Time) ([]Transaction, error)
	// FindBetweenLC finds all transactions which lamport clock value lies between startInclusive and endExclusive.
	// They are returned in order, sorted on lamport clock value.
	FindBetweenLC(ctx context.Context, startInclusive uint32, endExclusive uint32) ([]Transaction, error)
	// GetByPayloadHash retrieves all transactions that refer to the specified payload.
	GetByPayloadHash(ctx context.Context, payloadHash hash.SHA256Hash) ([]Transaction, error)
	// GetTransaction returns the transaction from local storage
	GetTransaction(ctx context.Context, hash hash.SHA256Hash) (Transaction, error)
	// IsPresent returns true if a transaction is present in the DAG
	IsPresent(context.Context, hash.SHA256Hash) (bool, error)
	// PayloadHashes applies the visitor function to the payload hashes of all transactions, in random order.
	PayloadHashes(ctx context.Context, visitor func(payloadHash hash.SHA256Hash) error) error
	// RegisterObserver allows observers to be notified when a transaction is added to the DAG.
	// If the observer needs to be called within the transaction, transactional must be true.
	RegisterObserver(observer Observer, transactional bool)
	// Subscribe lets an application subscribe to a specific type of transaction. When a new transaction is received
	// the `receiver` function is called. If an asterisk (`*`) is specified as `payloadType` the receiver is subscribed
	// to all payload types.
	Subscribe(eventType EventType, payloadType string, receiver Receiver)
	// Shutdown the DB
	Shutdown() error
	// Start the publisher and verifier
	Start() error
	// Statistics returns data for the statistics page
	Statistics(ctx context.Context) Statistics
	// Verify checks the integrity of the DAG. Should be called when it's loaded, e.g. from disk.
	Verify(ctx context.Context) error
	// Walk visits every node of the DAG, starting at the given hash working its way down each level until every leaf is visited.
	// when startAt is an empty hash, the walker starts at the root node.
	// The walker will resolve the given starting hash to a clock value.
	// The walk will be clock based so some transactions may be revisited due to existing branches.
	// Precautions must be taken to handle revisited transactions.
	Walk(ctx context.Context, visitor Visitor, startAt hash.SHA256Hash) error
	// XOR returns the xor of all transaction references between the DAG root and the clock closest to the requested clock value.
	// This closest clock value is also returned, and is defined as the lowest of:
	//	- upper-limit of the page that contains the requested clock
	//	- highest lamport clock in the DAG
	// A requested clock of math.MaxUint32 will return the xor of the entire DAG
	XOR(ctx context.Context, reqClock uint32) (hash.SHA256Hash, uint32)
	// IBLT returns the iblt of all transaction references between the DAG root and the clock closest to the requested clock value.
	// This closest clock value is also returned, and is defined as the lowest of:
	//	- upper-limit of the page that contains the requested clock
	//	- highest lamport clock in the DAG
	// A requested clock of math.MaxUint32 will return the iblt of the entire DAG
	IBLT(ctx context.Context, reqClock uint32) (tree.Iblt, uint32)
}

// Statistics holds data about the current state of the DAG.
type Statistics struct {
	// NumberOfTransactions contains the number of transactions on the DAG
	NumberOfTransactions int
	// DataSize contains the size of the DAG in bytes
	DataSize int
}

// Publisher defines the interface for types that publish Nuts Network transactions.
type Publisher interface {
	// ConfigureCallbacks subsribes the publisher on the state callbacks
	ConfigureCallbacks(state State)
	// Subscribe lets an application subscribe to a specific type of transaction. When a new transaction is received
	// the `receiver` function is called. If an asterisk (`*`) is specified as `payloadType` the receiver is subscribed
	// to all payload types.
	Subscribe(eventType EventType, payloadType string, receiver Receiver)
	// Start starts the publisher.
	Start() error
}

// EventType defines a type for specifying the kind of events that can be published/subscribed on the Publisher.
type EventType string

const (
	// TransactionAddedEvent is called when a transaction is added to the DAG. Its payload may not be present.
	TransactionAddedEvent EventType = "TRANSACTION_ADDED"
	// TransactionPayloadAddedEvent is called when a transaction is added to the DAG including its payload.
	TransactionPayloadAddedEvent EventType = "TRANSACTION_PAYLOAD_ADDED"
)

// Receiver defines a function for processing transactions when walking the DAG.
type Receiver func(transaction Transaction, payload []byte) error

// Visitor defines the contract for a function that visits the DAG. If the function returns `false` it stops walking the DAG.
type Visitor func(ctx context.Context, transaction Transaction) bool

// PayloadStore defines the interface for types that store and read transaction payloads.
type PayloadStore interface {
	PayloadReader
	PayloadWriter
	// ReadManyPayloads allows the caller read many payloads in an optimized fashion.
	ReadManyPayloads(ctx context.Context, consumer func(context.Context, PayloadReader) error) error
}

// PayloadWriter defines the interface for types that store transaction payloads.
type PayloadWriter interface {
	// WritePayload writes contents for the specified payload, identified by the given hash. Implementations must make
	// sure the hash matches the given contents.
	WritePayload(ctx context.Context, payloadHash hash.SHA256Hash, data []byte) error
}

// PayloadReader defines the interface for types that read transaction payloads.
type PayloadReader interface {
	// IsPayloadPresent checks whether the contents for the given transaction are present.
	IsPayloadPresent(ctx context.Context, payloadHash hash.SHA256Hash) (bool, error)

	// ReadPayload reads the contents for the specified payload, identified by the given hash. If contents can't be found,
	// nil is returned. If something (else) goes wrong an error is returned.
	ReadPayload(ctx context.Context, payloadHash hash.SHA256Hash) ([]byte, error)
}

// Observer defines the signature of an observer which can be called by an Observable.
type Observer func(ctx context.Context, transaction Transaction, payload []byte)

// MinTime returns the minimum value for time.Time
func MinTime() time.Time {
	return time.Time{}
}

// MaxTime returns the maximum value for time.Time. Taken from https://stackoverflow.com/questions/25065055/what-is-the-maximum-time-time-in-go
func MaxTime() time.Time {
	return time.Unix(1<<63-62135596801, 999999999)
}
