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

	"github.com/nuts-foundation/nuts-node/crypto/hash"
)

// AnyPayloadType is a wildcard that matches with any payload type.
const AnyPayloadType = "*"

var errRootAlreadyExists = errors.New("root transaction already exists")
var errNoClockValue = errors.New("missing clock value")

// DAG is a directed acyclic graph consisting of nodes (transactions) referring to preceding nodes.
type DAG interface {
	// Observable allows observers to be notified when a transaction is added to the DAG.
	Observable
	// Add adds one or more transactions to the DAG. If it can't be added an error is returned. Nil entries are ignored.
	Add(ctx context.Context, transactions ...Transaction) error
	// Walk visits every node of the DAG, starting at the given hash working its way down each level until every leaf is visited.
	// when startAt is an empty hash, the walker starts at the root node.
	// The walker will resolve the given starting hash to a clock value.
	// The walk will be clock based so some transactions may be revisited due to existing branches.
	// Precautions must be taken to handle revisited transactions.
	Walk(ctx context.Context, visitor Visitor, startAt hash.SHA256Hash) error
	// FindBetween finds all transactions which signing time lies between startInclude and endExclusive.
	// It returns the transactions in DAG walking order.
	FindBetween(ctx context.Context, startInclusive time.Time, endExclusive time.Time) ([]Transaction, error)
	// Get retrieves a specific transaction from the DAG. If it isn't found, nil is returned.
	Get(ctx context.Context, ref hash.SHA256Hash) (Transaction, error)
	// GetByPayloadHash retrieves all transactions that refer to the specified payload.
	GetByPayloadHash(ctx context.Context, payloadHash hash.SHA256Hash) ([]Transaction, error)
	// PayloadHashes applies the visitor function to the payload hashes of all transactions, in random order.
	PayloadHashes(ctx context.Context, visitor func(payloadHash hash.SHA256Hash) error) error
	// IsPresent checks whether the specified transaction exists on the DAG.
	IsPresent(ctx context.Context, ref hash.SHA256Hash) (bool, error)
	// Heads returns all unmerged heads, which are transactions where no other transactions point to as `prev`. To be used
	// as `prevs` parameter when adding a new transaction.
	Heads(ctx context.Context) []hash.SHA256Hash
	// Verify checks the integrity of the DAG. Should be called when it's loaded, e.g. from disk.
	Verify(ctx context.Context) error
	// Statistics returns data for the statistics page
	Statistics(ctx context.Context) Statistics
	// Migrate makes changes to the DB when needed
	Migrate() error
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
	// Subscribe lets an application subscribe to a specific type of transaction. When a new transaction is received
	// the `receiver` function is called. If an asterisk (`*`) is specified as `payloadType` the receiver is subscribed
	// to all payload types.
	Subscribe(payloadType string, receiver Receiver)
	// Start starts the publisher.
	Start() error
}

// Receiver defines a function for processing transactions when walking the DAG.
type Receiver func(transaction Transaction, payload []byte) error

// WalkerAlgorithm defines the interface for a type that can walk the DAG.
type WalkerAlgorithm interface {
	// walk visits every node of the DAG, starting at the given start node and working down each level until every leaf is visited.
	// numberOfNodes is an indicative number of nodes that's expected to be visited. It's used for optimizing memory usage.
	// getFn is a function for reading a transaction from the DAG using the given ref hash. If not found nil must be returned.
	// nextsFn is a function for reading a transaction's nexts using the given ref hash. If not found nil must be returned.
	walk(ctx context.Context, visitor Visitor, startAt hash.SHA256Hash, getFn func(hash.SHA256Hash) (Transaction, error), nextsFn func(hash.SHA256Hash) ([]hash.SHA256Hash, error)) error
}

// Visitor defines the contract for a function that visits the DAG. If the function returns `false` it stops walking the DAG.
type Visitor func(ctx context.Context, transaction Transaction) bool

// PayloadStore defines the interface for types that store and read transaction payloads.
type PayloadStore interface {
	// Observable allows observers to be notified when payload is written to the store.
	Observable
	PayloadReader
	PayloadWriter
	// ReadMany allows the caller read many payloads in an optimized fashion.
	ReadMany(ctx context.Context, consumer func(context.Context, PayloadReader) error) error
}

// PayloadWriter defines the interface for types that store transaction payloads.
type PayloadWriter interface {
	// WritePayload writes contents for the specified payload, identified by the given hash. Implementations must make
	// sure the hash matches the given contents.
	WritePayload(ctx context.Context, payloadHash hash.SHA256Hash, data []byte) error
}

// PayloadReader defines the interface for types that read transaction payloads.
type PayloadReader interface {
	// IsPresent checks whether the contents for the given transaction are present.
	IsPresent(ctx context.Context, payloadHash hash.SHA256Hash) (bool, error)

	// ReadPayload reads the contents for the specified payload, identified by the given hash. If contents can't be found,
	// nil is returned. If something (else) goes wrong an error is returned.
	ReadPayload(ctx context.Context, payloadHash hash.SHA256Hash) ([]byte, error)
}

// Observer defines the signature of an observer which can be called by an Observable.
type Observer func(ctx context.Context, subject interface{})

// Observable defines the interfaces for types that can be observed.
type Observable interface {
	RegisterObserver(observer Observer)
}

// MinTime returns the minimum value for time.Time
func MinTime() time.Time {
	return time.Time{}
}

// MaxTime returns the maximum value for time.Time. Taken from https://stackoverflow.com/questions/25065055/what-is-the-maximum-time-time-in-go
func MaxTime() time.Time {
	return time.Unix(1<<63-62135596801, 999999999)
}
