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
	"container/list"
	"errors"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"sort"
)

var errRootAlreadyExists = errors.New("root document already exists")

// DAG is a directed acyclic graph consisting of nodes (documents) referring to preceding nodes.
type DAG interface {
	Publisher
	// Add adds one or more documents to the DAG. If it can't be added an error is returned. Nil entries are ignored.
	Add(documents ...Document) error
	// MissingDocuments returns the hashes of the documents we know we are missing and should still be resolved.
	MissingDocuments() []hash.SHA256Hash
	// Walk visits every node of the DAG, starting at the given hash working its way down each level until every leaf is visited.
	// when startAt is an empty hash, the walker starts at the root node.
	Walk(walker Walker, visitor Visitor, startAt hash.SHA256Hash) error
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
	// Subscribe lets an application subscribe to a specific type of document. When a new document is received (for the
	// first time) the `receiver` function is called.
	Subscribe(documentType string, receiver Receiver)
}

// Receiver defines a function for processing documents when walking the DAG.
type Receiver func(document Document, payload []byte) error

// Walker defines the interface for a type that can walk the DAG.
type Walker interface {
	// walk visits every node of the DAG, starting at the given start node and working down each level until every leaf is visited.
	// numberOfNodes is an indicative number of nodes that's expected to be visited. It's used for optimizing memory usage.
	// getFn is a function for reading a document from the DAG using the given ref hash. If not found nil must be returned.
	// nextsFn is a function for reading a document's nexts using the given ref hash. If not found nil must be returned.
	walk(visitor Visitor, startAt hash.SHA256Hash, getFn func(hash.SHA256Hash) (Document, error), nextsFn func(hash.SHA256Hash) ([]hash.SHA256Hash, error), numberOfNodes int) error
}

// BFSWalker walks the DAG using the Breadth-First-Search (BFS) as described by Anany Levitin in "The Design & Analysis of Algorithms".
// It visits the whole tree level for level (breadth first vs depth first). It works by taking a node from queue and
// then adds the node's children (downward edges) to the queue. It starts by adding the root node to the queue and
// loops over the queue until empty, meaning all nodes reachable from the root node have been visited. Since our
// DAG contains merges (two parents referring to the same child node) we also keep a map to avoid visiting a
// merger node twice.
//
// This also means we have to make sure we don't visit the merger node before all of its previous nodes have been
// visited, which BFS doesn't account for. If that happens we skip the node without marking it as visited,
// so it will be visited again when the unvisited previous node is visited, which re-adds the merger node to the queue.
type BFSWalker struct{}

func (w BFSWalker) walk(visitor Visitor, startAt hash.SHA256Hash, getFn func(hash.SHA256Hash) (Document, error), nextsFn func(hash.SHA256Hash) ([]hash.SHA256Hash, error), numberOfNodes int) error {
	queue := list.New()
	queue.PushBack(startAt)
	visitedDocuments := make(map[hash.SHA256Hash]bool, numberOfNodes)

ProcessQueueLoop:
	for queue.Len() > 0 {
		// Pop first element of queue
		front := queue.Front()
		queue.Remove(front)
		currentRef := front.Value.(hash.SHA256Hash)

		// Make sure we haven't already visited this node
		if _, visited := visitedDocuments[currentRef]; visited {
			continue
		}

		// Make sure all prevs have been visited. Otherwise just continue, it will be re-added to the queue when the
		// unvisited prev node is visited and re-adds this node to the processing queue.
		currentDocument, err := getFn(currentRef)
		if err != nil {
			return err
		}

		for _, prev := range currentDocument.Previous() {
			if _, visited := visitedDocuments[prev]; !visited {
				continue ProcessQueueLoop
			}
		}

		// Add child nodes to processing queue
		// Processing order of nodes on the same level doesn't really matter for correctness of the DAG travel
		// but it makes testing easier.
		if nexts, err := nextsFn(currentRef); err != nil {
			return err
		} else if nexts != nil {
			sortedEdges := make([]hash.SHA256Hash, 0, len(nexts))
			for _, nextNode := range nexts {
				sortedEdges = append(sortedEdges, nextNode)
			}
			sort.Slice(sortedEdges, func(i, j int) bool {
				return sortedEdges[i].Compare(sortedEdges[j]) < 0
			})
			for _, nextNode := range sortedEdges {
				queue.PushBack(nextNode)
			}
		}

		// Visit the node
		if !visitor(currentDocument) {
			break
		}

		// Mark this node as visited
		visitedDocuments[currentRef] = true
	}
	return nil
}

// Visitor defines the contract for a function that visits the DAG. If the function returns `false` it stops walking the DAG.
type Visitor func(document Document) bool

// PayloadStore defines the interface for types that store document payloads.
type PayloadStore interface {

	// IsPayloadPresent checks whether the contents for the given document are present.
	IsPayloadPresent(payloadHash hash.SHA256Hash) (bool, error)

	// ReadPayload reads the contents for the specified payload, identified by the given hash. If contents can't be found,
	// nil is returned. If something (else) goes wrong an error is returned.
	ReadPayload(payloadHash hash.SHA256Hash) ([]byte, error)

	// WritePayload writes contents for the specified payload, identified by the given hash. Implementations must make
	// sure the hash matches the given contents.
	WritePayload(payloadHash hash.SHA256Hash, data []byte) error
}
