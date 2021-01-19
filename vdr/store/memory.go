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

package store

import (
	"github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-network/pkg/model"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

// NewMemoryStore initializes a new in-memory store
func NewMemoryStore() types.Store {
	return &memory{
		store: map[string]versionedEntryList{},
	}
}

type versionedEntryList []memoryEntry

type memory struct {
	store map[string]versionedEntryList
}

type memoryEntry struct {
	document   did.Document
	metadata   types.DocumentMetadata
}

func (m *memory) Resolve(DID did.DID, metadata *types.ResolveMetaData) (*did.Document, *types.DocumentMetadata, error) {
	entries, ok := m.store[DID.String()]
	if !ok {
		return nil, nil, types.ErrNotFound
	}

	// filter on hash
	if !hash.Equals(entry.metadata.Hash) {
		return types.ErrUpdateOnOutdatedData
	}

	// check deactivated which according to RFC006 is the case when no controllers and authenticationMethods exist
	doc := entry.document
	if len(doc.Controller) == 0 && len(doc.Authentication) == 0 {
		return types.ErrDeactivated
	}

	// hashes must match
	if !hash.Equals(entry.metadata.Hash) {
		return types.ErrUpdateOnOutdatedData
	}

	return &entry.document, &entry.metadata, nil
}

func (m *memory) Write(DIDDocument did.Document, metadata types.DocumentMetadata) error {
	if _, ok := m.store[DIDDocument.ID.String()]; ok {
		return types.ErrDIDAlreadyExists
	}

	m.store[DIDDocument.ID.String()] = memoryEntry{
		document: DIDDocument,
		metadata: metadata,
	}
	return nil
}

func (m *memory) Update(DID did.DID, hash model.Hash, next did.Document, metadata types.DocumentMetadata) error {
	rmd := &types.ResolveMetaData{
		Hash: &hash,
	}

	// resolve will handle all the checks for us
	if _, _, err := m.Resolve(DID, rmd); err != nil {
		return err
	}

	m.store[DID.ID] = memoryEntry{
		document: next,
		metadata: metadata,
	}

	return nil
}
