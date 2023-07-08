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
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag/tree"
	"math"
)

var errRootAlreadyExists = errors.New("root transaction already exists")

// ErrTransactionNotFound is returned when a requested transaction is not found on the DAG
var ErrTransactionNotFound = errors.New("transaction not found")

// ErrPayloadNotFound is returned when the requested payload is not found
var ErrPayloadNotFound = errors.New("payload not found")

// State represents the Node transactional state. Mutations are done via this abstraction layer.
// Notifications are also done via this layer
type State interface {
	core.Diagnosable
	core.Migratable

	// WritePayload writes contents for the specified payload, identified by the given hash.
	// It also calls observers and therefore requires the transaction.
	WritePayload(ctx context.Context, transaction Transaction, payloadHash hash.SHA256Hash, data []byte) error
	// IsPayloadPresent checks whether the contents for the given transaction are present.
	IsPayloadPresent(ctx context.Context, payloadHash hash.SHA256Hash) (bool, error)
	// ReadPayload reads the contents for the specified payload, identified by the given hash. If contents can't be found,
	// ErrPayloadNotFound is returned. If something (else) goes wrong an error is returned.
	ReadPayload(ctx context.Context, payloadHash hash.SHA256Hash) ([]byte, error)
	// Add a transaction to the DAG. If it can't be added an error is returned.
	// If the transaction already exists, nothing is added and no observers are notified.
	// The payload may be passed as well. Allowing for better notification of observers
	Add(ctx context.Context, transactions Transaction, payload []byte) error
	// FindBetweenLC finds all transactions which lamport clock value lies between startInclusive and endExclusive.
	// They are returned in order: first sorted on lamport clock value, then on transaction reference (byte order).
	FindBetweenLC(ctx context.Context, startInclusive uint32, endExclusive uint32) ([]Transaction, error)
	// GetTransaction returns the transaction from local storage.
	// If contents can't be found, ErrTransactionNotFound is returned.
	GetTransaction(ctx context.Context, hash hash.SHA256Hash) (Transaction, error)
	// IsPresent returns true if a transaction is present in the DAG
	IsPresent(context.Context, hash.SHA256Hash) (bool, error)
	// Notifier creates a new Notifier.
	// It lets another part of the application receive events on new transactions. When a new transaction is received
	// the `receiver` function is called. Notifiers can be persistent and will survive restarts.
	// The name is used to keep different notifiers apart.
	// Filters can be used to receive specific transactions. Filters are added via the WithSelectionFilter() option.
	// A Notifier should only be created during `configuration` step since the `start` step will redeliver all events that have not been delivered yet.
	// Returns an error when the Notifier already exists
	Notifier(name string, receiver ReceiverFn, filters ...NotifierOption) (Notifier, error)
	// Notifiers returns all registered notifiers
	Notifiers() []Notifier
	// Head returns the reference to a transactions that has not been referenced in the prevs of other transactions.
	// Returns hash.EmptyHash when no head is stored.
	Head(ctx context.Context) (hash.SHA256Hash, error)
	// Shutdown the DB
	Shutdown() error
	// Start the publisher and verifier
	Start() error
	// Verify checks the integrity of the DAG. Should be called when it's loaded, e.g. from disk.
	Verify(ctx context.Context) error
	// XOR returns the xor of all transaction references between the DAG root and the clock closest to the requested clock value.
	// This closest clock value is also returned, and is defined as the lowest of:
	//	- upper-limit of the page that contains the requested clock
	//	- highest lamport clock in the DAG
	// A requested clock of math.MaxUint32 will return the xor of the entire DAG
	XOR(reqClock uint32) (hash.SHA256Hash, uint32)
	// IBLT returns the iblt of all transaction references between the DAG root and the clock closest to the requested clock value.
	// This closest clock value is also returned, and is defined as the lowest of:
	//	- upper-limit of the page that contains the requested clock
	//	- highest lamport clock in the DAG
	// A requested clock of math.MaxUint32 will return the iblt of the entire DAG
	IBLT(reqClock uint32) (tree.Iblt, uint32)

	// IncorrectStateDetected is called when the xor and LC value from a gossip message do NOT match the local state.
	IncorrectStateDetected()
	// CorrectStateDetected is called when the xor and LC value from a gossip message match the local state.
	CorrectStateDetected()
}

// Statistics holds data about the current state of the DAG.
type Statistics struct {
	// NumberOfTransactions contains the number of transactions on the DAG
	NumberOfTransactions uint
	// DataSize contains the size of the DAG in bytes
	DataSize int64
}

// Visitor defines the contract for a function that visits the DAG. If the function returns `false` it stops walking the DAG.
type Visitor func(transaction Transaction) bool

// PayloadStore defines the interface for types that store and read transaction payloads.
type PayloadStore interface {
	// IsPayloadPresent checks whether the contents for the given transaction are present.
	isPayloadPresent(tx stoabs.ReadTx, payloadHash hash.SHA256Hash) bool
	// ReadPayload reads the contents for the specified payload, identified by the given hash. If contents can't be found,
	// ErrPayloadNotFound is returned. If something (else) goes wrong an error is returned.
	readPayload(tx stoabs.ReadTx, payloadHash hash.SHA256Hash) ([]byte, error)
	// WritePayload writes contents for the specified payload, identified by the given hash.
	writePayload(tx stoabs.WriteTx, payloadHash hash.SHA256Hash, data []byte) error
}

// MaxLamportClock is the highest Lamport Clock value a transaction on the DAG can have.
const MaxLamportClock = math.MaxUint32
