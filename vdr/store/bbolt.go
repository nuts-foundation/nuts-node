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
	"time"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-leia"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	vdr "github.com/nuts-foundation/nuts-node/vdr/types"
)

type documentEntry struct {
	Document did.Document			`json:"document"`
	Metadata vdr.DocumentMetadata	`json:"metadata"`
}

type bboltStore struct {
	db leia.Store
}

var refFunc = func(doc leia.Document) leia.Reference {
	entry := &documentEntry{}

	if err := json.Unmarshal(doc.Bytes(), entry); err != nil {
		return nil
	}

	return entry.Metadata.Hash.Slice()
}

// NewBBoltStore returns an instance of a BBolt based VDR store
func NewBBoltStore(dbLoc string) (vdr.Store, error) {
	store, err := leia.NewStore(dbLoc, false)
	if err != nil {
		return nil, err
	}

	collection := store.Collection("vdr", refFunc)

	// more indices can be added when needed to reduce Iteration
	collection.AddIndex(leia.NewIndex("id", leia.NewFieldIndexer("document.id")))

	return &bboltStore{db: store}, nil
}

func (store *bboltStore) collection() leia.Collection {
	return store.db.Collection("vdr", refFunc)
}

// Iterate loops over all the latest versions of the stored DID Documents and applies fn
func (store *bboltStore) Iterate(fn vdr.DocIterator) error {
	return store.collection().Iterate(nil, func(key leia.Reference, value []byte) error {
		entry := &documentEntry{}

		if err := json.Unmarshal(value, entry); err != nil {
			return nil
		}
		fn(entry.Document, entry.Metadata)

		return nil
	})
}

// Resolve returns the DID Document for the provided DID
func (store *bboltStore) Resolve(id did.DID, metadata *vdr.ResolveMetadata) (*did.Document, *vdr.DocumentMetadata, error) {
	if metadata != nil && metadata.Hash != nil {
		bytes, err := store.collection().Get(metadata.Hash.Slice())
		if err != nil {
			return nil, nil, err
		}

		if bytes == nil {
			return nil, nil, vdr.ErrNotFound
		}

		entry := documentEntry{}
		if err = json.Unmarshal(bytes.Bytes(), &entry); err != nil {
			return nil, nil, err
		}

		return &entry.Document, &entry.Metadata, nil
	}

	query := createQuery(id, metadata)

	results, err := store.collection().Find(query)
	if err != nil {
		return nil, nil, err
	}

	for _, docBytes := range results {
		entry := documentEntry{}
		if err = json.Unmarshal(docBytes.Bytes(), &entry); err != nil {
			return nil, nil, err
		}
		if entry.Metadata.Next == nil {
			return &entry.Document, &entry.Metadata, nil
		}
	}

	return nil, nil, vdr.ErrNotFound
}

func createQuery(id did.DID, metadata *vdr.ResolveMetadata) leia.Query {
	q := leia.New(leia.Eq("document.id", id.String()))

	if metadata == nil {
		return q
	}

	if metadata.SourceTransaction != nil {
		q = q.And(leia.Eq("metadata.txs", metadata.SourceTransaction.String()))
	}

	if !metadata.AllowDeactivated {
		q.And(leia.Eq("metadata.deactivated", false))
	}

	if metadata.ResolveTime != nil {
		q = q.And(leia.Range("metadata.created", int64(0), metadata.ResolveTime.Unix()))
		// or nil?
		//q = q.And(leia.Range("metadata.updated", metadata.ResolveTime.Unix(), ^uint(0)))
	}

	return q
}

// Write writes a DID Document
func (store *bboltStore) Write(document did.Document, metadata vdr.DocumentMetadata) error {
	data, err := json.Marshal(documentEntry{
		Document: document,
		Metadata: metadata,
	})
	if err != nil {
		return err
	}

	if err := store.collection().Add([]leia.Document{leia.DocumentFromBytes(data)}); err != nil {
		return err
	}

	return nil
}

// Update replaces the DID document identified by DID with the nextVersion
func (store *bboltStore) Update(id did.DID, current hash.SHA256Hash, next did.Document, metadata *vdr.DocumentMetadata) error {
	curr, meta, err := store.Resolve(id, &vdr.ResolveMetadata{Hash: &current})
	if err != nil {
		return err
	}

	// store new
	metadata.Previous = &current
	if err = store.Write(next, *metadata); err != nil {
		return err
	}

	// update old
	meta.Next = &metadata.Hash
	now := time.Now()
	meta.Updated = &now

	return store.Write(*curr, *meta)
}
