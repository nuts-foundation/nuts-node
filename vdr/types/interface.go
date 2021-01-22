/*
 * Nuts node
 * Copyright (C) 2021 Nuts community
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package types

import (
	"github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
)

// DocResolver is the interface that groups all the DID Document read methods
type DocResolver interface {
	// Resolve returns the DID document using on the given DID or ErrNotFound if not found.
	// If metadata is provided then the result is filtered or scoped on that metadata
	// If metadata is not provided the latest version is returned
	// If something goes wrong an error is returned.
	Resolve(DID did.DID, metadata *ResolveMetaData) (*did.Document, *DocumentMetadata, error)
}

// DocCreator is the interface that wraps the Create method
type DocCreator interface {
	// Create creates a new DID document and returns it.
	// The ID in the provided DID document will be ignored and a new one will be generated
	// If something goes wrong an error is returned.
	// Implementors should generate private key and store it in a secure backend
	Create() (*did.Document, error)
}

// DocWriter is the interface that groups al the DID Document write methods
type DocWriter interface {
	// Write writes a DID Document.
	// Returns ErrDIDAlreadyExists when DID already exists
	// When a document already exists, the Update should be used instead
	Write(DIDDocument did.Document, metadata DocumentMetadata) error
}

// DocUpdater is the interface that defines functions that alter the state of a DID document
type DocUpdater interface {
	// Update replaces the DID document identified by DID with the nextVersion
	// To prevent updating stale data a hash of the current version should be provided.
	// If the given hash does not represents the current version, a ErrUpdateOnOutdatedData is returned
	// If the DID Document is not found or not local a ErrNotFound is returned
	// If the DID Document is not active a ErrDeactivated is returned
	Update(DID did.DID, current hash.SHA256Hash, next did.Document, metadata *DocumentMetadata) error
}

// DocDeactivator is the interface that defines functions to deactivate DID Docs
// Deactivation will be done in such a way that a DID doc cannot be used / activated anymore.
type DocDeactivator interface {
	// To prevent updating stale data a hash of the current version should be provided.
	// If the given hash does not represents the current version, a ErrUpdateOnOutdatedData is returned
	// If the DID Document is not found or not local a ErrNotFound is returned
	// If the DID Document is not active a ErrDeactivated is returned
	Deactivate(DID did.DID, current hash.SHA256Hash)
}

// Store is the interface that groups all low level VDR DID storage operations.
type Store interface {
	DocResolver
	DocWriter
	DocUpdater
}

// VDR defines the public end facing methods for the Verifiable Data Registry.
type VDR interface {
	DocResolver
	DocCreator
	DocUpdater
	DocDeactivator
}
