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

type versionedEntryList []*memoryEntry

// filterFunc returns true if value must be kept
type filterFunc func(e memoryEntry) bool

func (list versionedEntryList) filter(f filterFunc) versionedEntryList {
	var vel versionedEntryList
	for _, entry := range list {
		if f(*entry) {
			vel = append(vel, entry)
		}
	}
	return vel
}

func (list versionedEntryList) last() (*memoryEntry, error) {
	if len(list) == 0 {
		return nil, types.ErrNotFound
	}
	return list[len(list)-1], nil
}

type memory struct {
	store map[string]versionedEntryList
}

type memoryEntry struct {
	document   did.Document
	metadata   types.DocumentMetadata
	next 	   *memoryEntry
}

func (me memoryEntry) isDeactivated() bool {
	if len(me.document.Controller) == 0 && len(me.document.Authentication) == 0 {
		return true
	}
	return false
}

func (m *memory) Resolve(DID did.DID, metadata *types.ResolveMetaData) (*did.Document, *types.DocumentMetadata, error) {
	entries, ok := m.store[DID.String()]
	if !ok {
		return nil, nil, types.ErrNotFound
	}

	if metadata != nil {
		// filter on hash
		if metadata.Hash != nil {
			entries = entries.filter(func (e memoryEntry) bool{
				return metadata.Hash.Equals(e.metadata.Hash)
			})
		}

		// filter on isDeactivated
		if !metadata.AllowDeactivated {
			entries = entries.filter(func (e memoryEntry) bool{
				return !e.isDeactivated()
			})
		}

		// filter on time
		if metadata.ResolveTime != nil {
			entries = entries.filter(timeSelectionFilter(*metadata))
		}
	}

	entry, err := entries.last()
	if err != nil {
		return nil, nil, err
	}

	return &entry.document, &entry.metadata, nil
}

// timeSelectionFilter checks if an entry is after the created, after the updated field if present but before the updated field of the next entry
func timeSelectionFilter(metadata types.ResolveMetaData) filterFunc {
	return func(e memoryEntry) bool {
		if e.metadata.Created.After(*metadata.ResolveTime) {
			return false
		}

		if e.metadata.Updated != nil {
			if e.metadata.Updated.After(*metadata.ResolveTime) {
				// this specific version is created later
				return false
			}
		}

		if e.next != nil {
			// a next must always have an updated field
			// the next version is created later, indicating this version is valid
			return e.next.metadata.Updated.After(*metadata.ResolveTime)
		}

		// last record in line
		return true
	}
}

func (m *memory) Write(DIDDocument did.Document, metadata types.DocumentMetadata) error {
	if _, ok := m.store[DIDDocument.ID.String()]; ok {
		return types.ErrDIDAlreadyExists
	}

	m.store[DIDDocument.ID.String()] = versionedEntryList{
		&memoryEntry{
			document: DIDDocument,
			metadata: metadata,
		},
	}

	return nil
}

// Update also updates the Updated field of the latest version
func (m *memory) Update(DID did.DID, hash model.Hash, next did.Document, metadata types.DocumentMetadata) error {
	entries, ok := m.store[DID.String()]
	if !ok {
		return types.ErrNotFound
	}

	// latest version is to be updated
	entry, _ := entries.last()

	if entry.isDeactivated() {
		return types.ErrDeactivated
	}

	// hashes must match
	if !hash.Equals(entry.metadata.Hash) {
		return types.ErrUpdateOnOutdatedData
	}

	newEntry := &memoryEntry{
		document: next,
		metadata: metadata,
	}

	// update next in last document
	entry.next = newEntry

	m.store[DID.String()] = append(entries, newEntry)

	return nil
}
