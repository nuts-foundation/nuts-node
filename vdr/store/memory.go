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
	"encoding/json"
	"github.com/nuts-foundation/go-did/did"
	vdr "github.com/nuts-foundation/nuts-node/vdr/types"
	"sync"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
)

// NewMemoryStore initializes a new in-memory store
// All actions on the store are thread safe.
func NewMemoryStore() vdr.Store {
	return &memory{
		store: map[string]versionedEntryList{},
		mutex: sync.Mutex{},
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
		return nil, vdr.ErrNotFound
	}
	return list[len(list)-1], nil
}

type memory struct {
	store map[string]versionedEntryList
	mutex sync.Mutex
}

type memoryEntry struct {
	document did.Document
	metadata vdr.DocumentMetadata
	next     *memoryEntry
}

func (me memoryEntry) isDeactivated() bool {
	return len(me.document.Controller) == 0 && len(me.document.Authentication) == 0
}

// Resolve implements the DocResolver.
// Resolves a DID document and returns a deep copy of the data in memory.
func (m *memory) Resolve(id did.DID, metadata *vdr.ResolveMetadata) (*did.Document, *vdr.DocumentMetadata, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	entries, ok := m.store[id.String()]
	if !ok {
		return nil, nil, vdr.ErrNotFound
	}

	if metadata != nil {
		// filter on hash
		if metadata.Hash != nil {
			entries = entries.filter(func(e memoryEntry) bool {
				return metadata.Hash.Equals(e.metadata.Hash)
			})
		}

		// filter on isDeactivated
		if !metadata.AllowDeactivated {
			entries = entries.filter(func(e memoryEntry) bool {
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

	// return a deep copy
	copyEntry, err := deepCopy(entry)
	if err != nil {
		return nil, nil, err
	}

	return &copyEntry.document, &copyEntry.metadata, nil
}

// deepCopy returns a deep copy of a memoryEntry
func deepCopy(entry *memoryEntry) (*memoryEntry, error) {
	// deep copy document
	// see https://github.com/nuts-foundation/go-did/issues/15
	docCopy := did.Document{}
	docJSON, err := json.Marshal(entry.document)
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(docJSON, &docCopy); err != nil {
		return nil, err
	}

	// deep copy metadata
	metadataCopy := entry.metadata.Copy()

	return &memoryEntry{
		document: docCopy,
		metadata: metadataCopy,
	}, nil
}

// timeSelectionFilter checks if an entry is after the created, after the updated field if present but before the updated field of the next entry
func timeSelectionFilter(metadata vdr.ResolveMetadata) filterFunc {
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

// Write implements the DocWriteWriter interface and writes a DIDDocument with the provided metadata to the memory store.
func (m *memory) Write(document did.Document, metadata vdr.DocumentMetadata) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if _, ok := m.store[document.ID.String()]; ok {
		return vdr.ErrDIDAlreadyExists
	}

	m.store[document.ID.String()] = versionedEntryList{
		&memoryEntry{
			document: document,
			metadata: metadata,
		},
	}

	return nil
}

// Update implements the DocUpdater interface.
// It updates existing DIDDocument in the memory store with provided document and metadata.
// It does not check if the timestamp in the metadata make sense or if the metadata.hash matches the hash
// of the next version. The version field is also not checked.
func (m *memory) Update(id did.DID, current hash.SHA256Hash, next did.Document, metadata *vdr.DocumentMetadata) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	entries, ok := m.store[id.String()]
	if !ok {
		return vdr.ErrNotFound
	}

	// latest version is to be updated
	entry, _ := entries.last()

	if entry.isDeactivated() {
		return vdr.ErrDeactivated
	}

	// hashes must match
	if !current.Equals(entry.metadata.Hash) {
		return vdr.ErrUpdateOnOutdatedData
	}

	newEntry := &memoryEntry{
		document: next,
		metadata: *metadata,
	}

	// update next in last document
	entry.next = newEntry

	m.store[id.String()] = append(entries, newEntry)

	return nil
}
