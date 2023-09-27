/*
 * Copyright (C) 2022 Nuts community
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

package didstore

import (
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/vdr/management"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
)

// Store is the interface that groups all low level VDR DID storage operations.
type Store interface {
	// Add a DID Document to the store. The store will place it on the timeline and reprocess other versions if needed
	Add(didDocument did.Document, transaction Transaction) error
	// Conflicted iterates over all conflicted documents
	Conflicted(fn management.DocIterator) error
	// ConflictedCount returns the number of conflicted DID Documents
	ConflictedCount() (uint, error)
	// DocumentCount returns the number of DID Documents
	DocumentCount() (uint, error)
	// Iterate loops over all the latest versions of the stored DID Documents and applies fn.
	// Calling any of the Store's functions from the given fn might cause a deadlock.
	Iterate(fn management.DocIterator) error
	// Resolve returns the DID Document for the provided DID.
	// If metadata is not provided the latest version is returned.
	// If metadata is provided then the result is filtered or scoped on that metadata.
	// It returns vdr.ErrNotFound if there are no corresponding DID documents or when the DID Documents are disjoint with the provided ResolveMetadata.
	// It returns vdr.ErrDeactivated if no metadata is given and the latest version of the DID Document is deactivated.
	Resolve(id did.DID, metadata *resolver.ResolveMetadata) (*did.Document, *resolver.DocumentMetadata, error)
}

// Transaction is an alias to the didstore.event. Internally to the didstore it's an event based on a transaction.
// Using event as external name is very confusing, so there they are called transaction.
type Transaction event
