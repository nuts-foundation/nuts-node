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
	"context"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/vdr/management"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"net/url"
)

// VDR defines the public end facing methods for the Verifiable Data Registry.
type VDR interface {
	management.DocumentOwner
	management.DocCreator
	management.DocUpdater

	// Resolver returns the resolver for getting the DID document for a DID.
	Resolver() resolver.DIDResolver

	// ConflictedDocuments returns the DID Document and metadata of all documents with a conflict.
	ConflictedDocuments() ([]did.Document, []resolver.DocumentMetadata, error)

	// DeriveWebDIDDocument returns the did:web equivalent of the given Nuts DID. If it doesn't exist or is not owned by this node it returns an error.
	DeriveWebDIDDocument(ctx context.Context, baseURL url.URL, nutsDID did.DID) (*did.Document, error)
}
