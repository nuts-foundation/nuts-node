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
	crypto2 "crypto"
	"time"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag"
)

// Transactions is the interface that defines the API for creating, reading and subscribing to Nuts Network transactions.
type Transactions interface {
	// Subscribe makes a subscription for the specified document type. The receiver is called when a document
	// is received for the specified type.
	Subscribe(documentType string, receiver dag.Receiver)
	// GetDocumentPayload retrieves the document payload for the given document. If the document or payload is not found
	// nil is returned.
	GetDocumentPayload(documentRef hash.SHA256Hash) ([]byte, error)
	// GetDocument retrieves the document for the given reference. If the document is not known, an error is returned.
	GetDocument(documentRef hash.SHA256Hash) (dag.Document, error)
	// CreateDocument creates a new document with the specified payload, and signs it using the specified key.
	// If the key should be inside the document (instead of being referred to) `attachKey` should be true.
	CreateDocument(payloadType string, payload []byte, signingKeyID string, attachKey crypto2.PublicKey, timestamp time.Time, fieldsOpts ...dag.FieldOpt) (dag.Document, error)
	// ListDocuments returns all documents known to this Network instance.
	ListDocuments() ([]dag.Document, error)
	// AddPeer instructs the P2P layer to try to connect to a new peer on the given address. It's safe to call it
	// multiple times for the same address. If the P2P layer will attempt to connect to the address it returns `true`.
	AddPeer(address string) bool
}
