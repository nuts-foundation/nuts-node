/*
 * Copyright (C) 2023 Nuts community
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

package vdr

import (
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/vdr/didsubject"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"net/url"
)

// VDR defines the public end facing methods for the Verifiable Data Registry.
type VDR interface {
	// NutsDocumentManager returns the nuts document manager.
	// Deprecated
	NutsDocumentManager() didsubject.DocumentManager
	// DocumentOwner returns the document owner.
	DocumentOwner() didsubject.DocumentOwner

	// ResolveManaged resolves a DID document that is managed by the local node.
	ResolveManaged(id did.DID) (*did.Document, error)
	// Resolver returns the resolver for getting the DID document for a DID.
	Resolver() resolver.DIDResolver
	// ConflictedDocuments returns the DID Document and metadata of all documents with a conflict.
	ConflictedDocuments() ([]did.Document, []resolver.DocumentMetadata, error)
	// PublicURL returns the public URL of the Nuts node, which is used as base URL for web-based DIDs.
	PublicURL() *url.URL
}
