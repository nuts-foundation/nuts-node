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
	"encoding/json"
	"errors"

	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag/tree"
)

var errRootAlreadyExists = errors.New("root transaction already exists")

// State represents the Node transactional state. Mutations are done via this abstraction layer.
// Notifications are also done via this layer
type State interface {
	core.Diagnosable
	// WritePayload writes contents for the specified payload, identified by the given Hash.
	// It also calls observers and therefore requires the transaction.
	WritePayload(transaction Transaction, payloadHash hash.SHA256Hash, data []byte) error
	// IsPayloadPresent checks whether the contents for the given transaction are present.
	IsPayloadPresent(ctx context.Context, payloadHash hash.SHA256Hash) (bool, error)
	// ReadPayload reads the contents for the specified payload, identified by the given Hash. If contents can't be found,
	// nil is returned. If something (else) goes wrong an error is returned.
	ReadPayload(ctx context.Context, payloadHash hash.SHA256Hash) ([]byte, error)
	// Add a transaction to the DAG. If it can't be added an error is returned.
	// If the transaction already exists, nothing is added and no observers are notified.
	// The payload may be passed as well. Allowing for better notification of observers
	Add(ctx context.Context, transactions Transaction, payload []byte) error
	// FindBetweenLC finds all transactions which lamport clock value lies between startInclusive and endExclusive.
	// They are returned in order: first sorted on lamport clock value, then on transaction reference (byte order).
	FindBetweenLC(startInclusive uint32, endExclusive uint32) ([]Transaction, error)
	// GetTransaction returns the transaction from local storage
	GetTransaction(ctx context.Context, hash hash.SHA256Hash) (Transaction, error)
	// IsPresent returns true if a transaction is present in the DAG
	IsPresent(context.Context, hash.SHA256Hash) (bool, error)
	// Heads returns the references to all transactions that have not been referenced in the prevs of other transactions.
	Heads(ctx context.Context) []hash.SHA256Hash
	// Subscribe lets another part of the application subscribe to a specific type of transaction. When a new transaction is received
	// the `subscriber` function is called. Subscriptions can be persistent and will survive restarts.
	// The name is used to keep different subscribers apart.
	// Filters can be used to subscribe to specific transactions. Filters are added via the WithFilter() option.
	// Subscribe should only be called during the `configuration` step since the `start` step will auto-resume all jobs that have not finished yet.
	// Returns an error when the subscriber already exists
	Subscribe(name string, subscriber SubscriberFn, filters ...SubscriberOption) (Subscriber, error)
	// Shutdown the DB
	Shutdown() error
	// Start the publisher and verifier
	Start() error
	// Statistics returns data for the statistics page
	Statistics(ctx context.Context) Statistics
	// Verify checks the integrity of the DAG. Should be called when it's loaded, e.g. from disk.
	Verify() error
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
	IBLT(reqClock uint32) (tree.Iblt, uint32)
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
	// ReadPayload reads the contents for the specified payload, identified by the given Hash. If contents can't be found,
	// nil is returned. If something (else) goes wrong an error is returned.
	readPayload(tx stoabs.ReadTx, payloadHash hash.SHA256Hash) []byte
	// WritePayload writes contents for the specified payload, identified by the given Hash.
	writePayload(tx stoabs.WriteTx, payloadHash hash.SHA256Hash, data []byte) error
}

// Job is the metadata that is stored for a subscriber specific event
// The Hash is used as identifier for the Job.
type Job struct {
	Type        string          `json:"type"`
	Hash        hash.SHA256Hash `json:"Hash"`
	Count       int             `json:"count"`
	Transaction Transaction     `json:"transaction"`
	Payload     []byte          `json:"payload"`
}

// SubscriberFn is the function type that needs to be registered for a subscriber
// Returns true if job is finished, false otherwise
type SubscriberFn func(job Job) (bool, error)

// SubscriptionFilter can be added to a subscription to filter out any unwanted transactions
// Returns true if the filter applies and the job needs to be executed
type SubscriptionFilter func(job Job) bool

// SubscriberOption sets an option on a subscriber
type SubscriberOption func(subscriber *subscriber)

// TODO move
func (j *Job) UnmarshalJSON(bytes []byte) error {
	tmp := &struct {
		Type        string          `json:"type"`
		Hash        hash.SHA256Hash `json:"Hash"`
		Count       int             `json:"count"`
		Transaction string          `json:"transaction"`
		Payload     []byte          `json:"payload"`
	}{}

	if err := json.Unmarshal(bytes, tmp); err != nil {
		return err
	}

	j.Type = tmp.Type
	j.Hash = tmp.Hash
	j.Count = tmp.Count
	j.Payload = tmp.Payload

	tx, err := ParseTransaction([]byte(tmp.Transaction))
	if err != nil {
		return err
	}
	j.Transaction = tx

	return nil
}
