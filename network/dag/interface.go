/*
 * Copyright (C) 2021. Nuts community
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
	"errors"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
)

var errRootAlreadyExists = errors.New("root document already exists")

// DAG is a directed acyclic graph consisting of nodes (documents) referring to preceding nodes.
type DAG interface {
	// Observable allows observers to be notified when a document is added to the DAG.
	Observable
	// Add adds one or more documents to the DAG. If it can't be added an error is returned. Nil entries are ignored.
	Add(documents ...Document) error
	// MissingDocuments returns the hashes of the documents we know we are missing and should still be resolved.
	MissingDocuments() []hash.SHA256Hash
	// Walk visits every node of the DAG, starting at the given hash working its way down each level until every leaf is visited.
	// when startAt is an empty hash, the walker starts at the root node.
	Walk(algo WalkerAlgorithm, visitor Visitor, startAt hash.SHA256Hash) error
	// Root returns the root hash of the DAG. If there's no root an empty hash is returned. If an error occurs, it is returned.
	Root() (hash.SHA256Hash, error)
	// Get retrieves a specific document from the DAG. If it isn't found, nil is returned.
	Get(ref hash.SHA256Hash) (Document, error)
	// GetByPayloadHash retrieves all documents that refer to the specified payload.
	GetByPayloadHash(payloadHash hash.SHA256Hash) ([]Document, error)
	// All retrieves all documents from the DAG.
	// TODO: This should go when there's a more optimized network protocol
	All() ([]Document, error)
	// IsPresent checks whether the specified document exists on the DAG.
	IsPresent(ref hash.SHA256Hash) (bool, error)
	// Heads returns all unmerged heads, which are documents where no other documents point to as `prev`. To be used
	// as `prevs` parameter when adding a new document.
	Heads() []hash.SHA256Hash
}

// Publisher defines the interface for types that publish Nuts Network documents.
type Publisher interface {
	// Subscribe lets an application subscribe to a specific type of document. When a new document is received
	//the `receiver` function is called.
	Subscribe(documentType string, receiver Receiver)
	// Start starts the publisher.
	Start()
}

// Receiver defines a function for processing documents when walking the DAG.
type Receiver func(document Document, payload []byte) error

// WalkerAlgorithm defines the interface for a type that can walk the DAG.
type WalkerAlgorithm interface {
	// walk visits every node of the DAG, starting at the given start node and working down each level until every leaf is visited.
	// numberOfNodes is an indicative number of nodes that's expected to be visited. It's used for optimizing memory usage.
	// getFn is a function for reading a document from the DAG using the given ref hash. If not found nil must be returned.
	// nextsFn is a function for reading a document's nexts using the given ref hash. If not found nil must be returned.
	walk(visitor Visitor, startAt hash.SHA256Hash, getFn func(hash.SHA256Hash) (Document, error), nextsFn func(hash.SHA256Hash) ([]hash.SHA256Hash, error)) error
}

// Visitor defines the contract for a function that visits the DAG. If the function returns `false` it stops walking the DAG.
type Visitor func(document Document) bool

// PayloadStore defines the interface for types that store and read document payloads.
type PayloadStore interface {
	// Observable allows observers to be notified when payload is written to the store.
	Observable
	PayloadWriter

	// IsPayloadPresent checks whether the contents for the given document are present.
	IsPresent(payloadHash hash.SHA256Hash) (bool, error)

	// ReadPayload reads the contents for the specified payload, identified by the given hash. If contents can't be found,
	// nil is returned. If something (else) goes wrong an error is returned.
	ReadPayload(payloadHash hash.SHA256Hash) ([]byte, error)
}

// PayloadWriter defines the interface for types that store document payloads.
type PayloadWriter interface {
	// WritePayload writes contents for the specified payload, identified by the given hash. Implementations must make
	// sure the hash matches the given contents.
	WritePayload(payloadHash hash.SHA256Hash, data []byte) error
}

// Observer defines the signature of a observer which can be called by an Observable.
type Observer func(subject interface{})

// Observable defines the interfaces for types that can be observed.
type Observable interface {
	RegisterObserver(observer Observer)
}
