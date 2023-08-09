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
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/storage"
	vdr "github.com/nuts-foundation/nuts-node/vdr/types"
)

var _ core.Configurable = (*store)(nil)

// didStoreName contains the name for the store
const didStoreName = "didstore"

// shelfs have a V2 postfix due to overlapping names with previous implementation
const (
	// latestShelf has DID as key and latest documentMetadata reference as value.
	latestShelf = "latestV2"
	// metadataShelf has the documentMetadata reference (DID concatenated with version number, starting at 0) as key and the metadataRecord as value
	metadataShelf = "metadataV2"
	// transactionIndexShelf has the transaction reference as key and payloadHash as value. Used for duplicate detection and document mergin
	transactionIndexShelf = "txRefV2"
	// documentShelf has payload hash as key and document as value
	documentShelf = "documentsV2"
	// eventShelf contains the eventList for this DID Document with the DID as key and eventList as value
	eventShelf = "eventsV2"
	// conflictedShelf contains all DIDs that are in a conflicted state. The DID is the key and a 0 byte is the value
	conflictedShelf = "conflictedV2"
	// statsShelf contains different statistics which are requested frequently: conflictedCount, documentCount
	statsShelf = "statsV2"
	// conflictedCountKey is the key used on the statsShelf to store the number of conflictedDocuments
	conflictedCountKey = "conflictedCount"
	// documentCountKey is the key used on the statsShelf to store the number of documents
	documentCountKey = "documentCount"
)

// conflictedDocument is a helper struct to store owned conflicted documents in memory
type conflictedDocument struct {
	didDocument did.Document
	metadata    documentMetadata
}

type store struct {
	db                  stoabs.KVStore
	storageProvider     storage.Provider
	conflictedDocuments map[string]conflictedDocument
}

// New returns a new vdrStore.Store that still needs to be initialized
func New(storageProvider storage.Provider) Store {
	return &store{
		storageProvider:     storageProvider,
		conflictedDocuments: map[string]conflictedDocument{},
	}
}

func (tl *store) Configure(_ core.ServerConfig) (err error) {
	tl.db, err = tl.storageProvider.GetKVStore(didStoreName, storage.PersistentStorageClass)
	if err != nil {
		return
	}
	err = tl.loadConflictedDocuments()
	return
}

// Add inserts the document version at the correct place and updates all later versions if needed
// The integrity of the document has already been checked by the DAG.
func (tl *store) Add(didDocument did.Document, transaction Transaction) error {
	// First write the document and transaction to the transactionIndexShelf and documentShelf.
	// This operation is duplicate save, since it uses hash values as key.
	// This operation must succeed because otherwise the second transaction will be broken forever.
	// Due to the way Redis works, there's no guarantee all the data is written transactionally when
	// executed in a single write operation.
	err := tl.db.Write(context.Background(), func(tx stoabs.WriteTx) error {
		// write document to documentShelf
		err := writeDocument(tx, didDocument, transaction)
		if err != nil {
			return fmt.Errorf("writeDocument failed: %w", err)
		}
		return nil
	}, stoabs.WithWriteLock())
	if err != nil {
		return fmt.Errorf("database error on commit: %w", err)
	}

	err = tl.db.Write(context.Background(), func(tx stoabs.WriteTx) error {
		currentEventList, err := readEventList(tx, didDocument.ID)
		if err != nil {
			return fmt.Errorf("read eventList failed: %w", err)
		}

		transaction.document = &didDocument
		if currentEventList.contains(event(transaction)) {
			return nil
		}

		index := currentEventList.insert(event(transaction))
		var base *event
		applyList := currentEventList.Events[index:]
		if index > 0 {
			base = &currentEventList.Events[index-1]
		}
		if err = tl.applyFrom(tx, base, applyList); err != nil {
			return fmt.Errorf("applying event list failed: %w", err)
		}
		return writeEventList(tx, currentEventList, didDocument.ID)
	}, stoabs.WithWriteLock())
	if err != nil {
		return fmt.Errorf("database error on commit: %w", err)
	}
	return nil
}

func (tl *store) Resolve(id did.DID, resolveMetadata *vdr.ResolveMetadata) (returnDocument *did.Document, returnMetadata *vdr.DocumentMetadata, txErr error) {
	txErr = tl.db.Read(context.Background(), func(tx stoabs.ReadTx) error {
		latestReader := tx.GetShelfReader(latestShelf)
		latestMetaRef, err := latestReader.Get(stoabs.BytesKey(id.String()))
		if err != nil && !errors.Is(err, stoabs.ErrKeyNotFound) {
			return err
		}

		if latestMetaRef == nil {
			return vdr.ErrNotFound
		}

		// loop over all versions
		for {
			metadata, err := readMetadata(tx, latestMetaRef)
			if err != nil {
				return fmt.Errorf("read metadata failed: %w", err)
			}

			if metadata.Deactivated && latestNonDeactivatedRequested(resolveMetadata) {
				// We're trying to resolve the latest, it should not return an older (active) version when deactivated
				return vdr.ErrDeactivated
			}
			if matches(metadata, resolveMetadata) {
				mdTmp := metadata.asVDRMetadata()
				returnMetadata = &mdTmp
				document, err := readDocument(tx, metadata.Hash)
				if err != nil {
					return fmt.Errorf("read document failed: %w", err)
				}
				returnDocument = &document
				return nil
			}
			if metadata.Version == 0 {
				break
			}
			latestMetaRef = []byte(fmt.Sprintf("%s%d", id.String(), metadata.Version-1))
		}
		return vdr.ErrNotFound
	})
	return
}

func (tl *store) Iterate(fn vdr.DocIterator) error {
	return tl.db.Read(context.Background(), func(tx stoabs.ReadTx) error {
		latestReader := tx.GetShelfReader(latestShelf)

		return latestReader.Iterate(func(didKey stoabs.Key, metadataRecordRef []byte) error {
			metadata, err := readMetadata(tx, metadataRecordRef)
			if err != nil {
				return fmt.Errorf("read metadata failed: %w", err)
			}

			var document did.Document
			document, err = readDocument(tx, metadata.Hash)
			if err != nil {
				return fmt.Errorf("read document failed: %w", err)
			}

			return fn(document, metadata.asVDRMetadata())
		}, stoabs.BytesKey{})
	})
}

func (tl *store) loadConflictedDocuments() error {
	err := tl.db.Read(context.Background(), func(tx stoabs.ReadTx) error {
		conflictedReader := tx.GetShelfReader(conflictedShelf)
		latestReader := tx.GetShelfReader(latestShelf)

		return conflictedReader.Iterate(func(key stoabs.Key, _ []byte) error {
			latestMetaRef, err := latestReader.Get(key)
			if err != nil && !errors.Is(err, stoabs.ErrKeyNotFound) {
				return err
			}
			if latestMetaRef == nil {
				return nil
			}
			metadata, err := readMetadata(tx, latestMetaRef)
			if err != nil {
				return fmt.Errorf("read metadata failed: %w", err)
			}

			document, err := readDocument(tx, metadata.Hash)
			if err != nil {
				return fmt.Errorf("read document failed: %w", err)
			}

			tl.conflictedDocuments[document.ID.String()] = conflictedDocument{
				didDocument: document,
				metadata:    metadata,
			}

			return nil
		}, stoabs.BytesKey{})
	})
	if err != nil {
		return fmt.Errorf("conflicted: database error on Read: %w", err)
	}
	return nil
}

func (tl *store) addCachedConflict(document did.Document, metadata documentMetadata) {
	tl.conflictedDocuments[document.ID.String()] = conflictedDocument{
		didDocument: document,
		metadata:    metadata,
	}
}

func (tl *store) removeCachedConflict(document did.Document) {
	delete(tl.conflictedDocuments, document.ID.String())
}

func (tl *store) Conflicted(fn vdr.DocIterator) error {
	for _, conflicted := range tl.conflictedDocuments {
		if err := fn(conflicted.didDocument, conflicted.metadata.asVDRMetadata()); err != nil {
			return err
		}
	}
	return nil
}

func (tl *store) ConflictedCount() (uint, error) {
	var count uint32

	err := tl.db.ReadShelf(context.Background(), statsShelf, func(reader stoabs.Reader) error {
		cBytes, err := reader.Get(stoabs.BytesKey(conflictedCountKey))
		if err != nil && !errors.Is(err, stoabs.ErrKeyNotFound) {
			return err
		}
		if len(cBytes) > 0 {
			count = binary.BigEndian.Uint32(cBytes)
		}
		return nil
	})

	return uint(count), err
}

func (tl *store) DocumentCount() (uint, error) {
	var count uint32

	err := tl.db.ReadShelf(context.Background(), statsShelf, func(reader stoabs.Reader) error {
		cBytes, err := reader.Get(stoabs.BytesKey(documentCountKey))
		if err != nil && !errors.Is(err, stoabs.ErrKeyNotFound) {
			return err
		}
		if len(cBytes) > 0 {
			count = binary.BigEndian.Uint32(cBytes)
		}
		return nil
	})

	return uint(count), err
}

func matches(metadata documentMetadata, resolveMetadata *vdr.ResolveMetadata) bool {
	if metadata.Deactivated && (resolveMetadata == nil || !resolveMetadata.AllowDeactivated) {
		return false
	}

	if resolveMetadata == nil {
		return true
	}

	// Filter on hash
	if resolveMetadata.Hash != nil && !metadata.Hash.Equals(*resolveMetadata.Hash) {
		return false
	}

	// Filter on creation and update time
	if resolveMetadata.ResolveTime != nil {
		resolveTime := *resolveMetadata.ResolveTime

		if metadata.Updated.After(resolveTime) {
			return false
		}

		if metadata.Created.After(resolveTime) {
			return false
		}
	}

	// Filter on SourceTransaction
	if resolveMetadata.SourceTransaction != nil {
		for _, keyTx := range metadata.SourceTransactions {
			if keyTx.Equals(*resolveMetadata.SourceTransaction) {
				return true
			}
		}
		return false
	}

	return true
}

// latestNonDeactivatedRequested is a combination of checks on the resolveMetadata when a deactivated document is resolved
// if no resolveMetadata is given the latest active document is requested, so it may not be deactivated
// if resolveTime, hash or sourceTransaction is given, most likely the latest version is not requested
// the deactivated check is then done in matches()
// finally, if the latest is requested and it is deactivated, the allowDeactivated flag is checked
func latestNonDeactivatedRequested(resolveMetadata *vdr.ResolveMetadata) bool {
	if resolveMetadata == nil {
		return true
	}
	if resolveMetadata.ResolveTime != nil {
		return false
	}
	if resolveMetadata.Hash != nil {
		return false
	}
	if resolveMetadata.SourceTransaction != nil {
		return false
	}
	return !resolveMetadata.AllowDeactivated
}
