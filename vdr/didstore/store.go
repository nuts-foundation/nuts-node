/*
 * Nuts node
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
 */

package didstore

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/storage"
	vdr "github.com/nuts-foundation/nuts-node/vdr/types"
)

const (
	// latestShelf has DID as key and latest documentMetadata reference as value.
	// shelfs have a V2 postfix due to overlapping names with previous implementation
	latestShelf = "latestV2"
	// metadataShelf has the documentMetadata reference (DID concatenated with version number, starting at 0) as key and the metadataRecord as value
	metadataShelf = "metadataV2"
	// transactionIndexShelf has the transaction reference as key and a zero byte as value. Used for duplicate detection
	transactionIndexShelf = "txRefV2"
	// documentShelf has payload hash as key and document as value
	documentShelf = "documentsV2"
	// eventShelf contains the eventList for this DID Document with the DID as key and eventList as value
	eventShelf = "eventsV2"
	// conflictedShelf contains all DIDs that are in a conflicted state. The DID is the key and a 0 byte is the value
	conflictedShelf = "conflictedV2"
	// statsShelf contains different statistics which are requested frequently: conflictedCount
	statsShelf = "statsV2"
	// conflictedCountKey is the key used on the statsShelf to store the number of conflictedDocuments
	conflictedCountKey = "conflictedCount"
	// documentCountKey is the key used on the statsShelf to store the number of documents
	documentCountKey = "documentCount"
	// didStoreName contains the name for the store
	didStoreName = "didstore"
)

type store struct {
	db              stoabs.KVStore
	storageProvider storage.Provider
}

// New returns a new vdrStore.Store that still needs to be initialized
func New(storageProvider storage.Provider) Store {
	return &store{
		storageProvider: storageProvider,
	}
}

func (tl *store) Configure(_ core.ServerConfig) (err error) {
	tl.db, err = tl.storageProvider.GetKVStore(didStoreName, storage.PersistentStorageClass)
	return err
}

// Add inserts the document version at the correct place and updates all later versions if needed
// The integrity of the document has already been checked by the DAG.
func (tl *store) Add(didDocument did.Document, transaction Transaction) error {
	// prevents parallel execution
	err := tl.db.Write(context.Background(), func(tx stoabs.WriteTx) error {
		if isDuplicate(tx, transaction) {
			return nil
		}

		currentEventList, err := readEventList(tx, didDocument.ID)
		if err != nil {
			return err
		}

		// write document to documentShelf
		err = writeDocument(tx, didDocument, transaction)
		if err != nil {
			return err
		}

		newEvent := transaction.toEvent()
		newEvent.document = &didDocument
		newEvent.metadata = &documentMetadata{
			Created:             transaction.SigningTime,
			Updated:             transaction.SigningTime,
			Hash:                transaction.PayloadHash,
			PreviousTransaction: transaction.Previous,
			SourceTransactions:  []hash.SHA256Hash{transaction.Ref},
			Deactivated:         isDeactivated(didDocument),
		}
		newEventList := currentEventList.copy()
		newEventList.insert(newEvent)

		base, applyList := currentEventList.updates(newEventList)
		if err = applyFrom(tx, base, applyList); err != nil {
			return err
		}
		return writeEventList(tx, newEventList, didDocument.ID)
	})
	if err != nil {
		return fmt.Errorf("add: database error on commit: %w", err)
	}
	return nil
}

func (tl *store) Resolve(id did.DID, resolveMetadata *vdr.ResolveMetadata) (returnDocument *did.Document, returnMetadata *vdr.DocumentMetadata, txErr error) {
	txErr = tl.db.Read(context.Background(), func(tx stoabs.ReadTx) error {
		latestReader := tx.GetShelfReader(latestShelf)
		latestMetaRef, _ := latestReader.Get(stoabs.BytesKey(id.String()))

		if latestMetaRef == nil {
			return vdr.ErrNotFound
		}

		// loop over all versions
		for {
			metadata, err := readMetadata(tx, latestMetaRef)
			if err != nil {
				return err
			}

			if metadata.Deactivated && resolveMetadata == nil {
				// We're trying to resolve the latest, it should not return an older (active) version when deactivated
				return vdr.ErrDeactivated
			}
			if matches(metadata, resolveMetadata) {
				mdTmp := metadata.asVDRMetadata()
				returnMetadata = &mdTmp
				document, err := readDocument(tx, metadata.Hash)
				if err != nil {
					return err
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
	err := tl.db.Read(context.Background(), func(tx stoabs.ReadTx) error {
		latestReader := tx.GetShelfReader(latestShelf)

		return latestReader.Iterate(func(didKey stoabs.Key, metadataRecordRef []byte) error {
			metadata, err := readMetadata(tx, metadataRecordRef)
			if err != nil {
				return err
			}

			var document did.Document
			document, err = readDocument(tx, metadata.Hash)
			if err != nil {
				return err
			}

			return fn(document, metadata.asVDRMetadata())
		}, stoabs.BytesKey{})
	})
	if err != nil {
		return fmt.Errorf("iterate: database error on Read: %w", err)
	}
	return nil
}

func (tl *store) Conflicted(fn vdr.DocIterator) error {
	err := tl.db.Read(context.Background(), func(tx stoabs.ReadTx) error {
		conflictedReader := tx.GetShelfReader(conflictedShelf)
		latestReader := tx.GetShelfReader(latestShelf)

		return conflictedReader.Iterate(func(key stoabs.Key, _ []byte) error {
			latestMetaRef, _ := latestReader.Get(key)
			if latestMetaRef == nil {
				return nil
			}
			metadata, err := readMetadata(tx, latestMetaRef)
			if err != nil {
				return err
			}

			document, err := readDocument(tx, metadata.Hash)
			if err != nil {
				return err
			}

			return fn(document, metadata.asVDRMetadata())
		}, stoabs.BytesKey{})
	})
	if err != nil {
		return fmt.Errorf("conflicted: database error on Read: %w", err)
	}
	return nil
}

func (tl *store) ConflictedCount() (uint, error) {
	var count uint32

	err := tl.db.ReadShelf(context.Background(), statsShelf, func(reader stoabs.Reader) error {
		cBytes, err := reader.Get(stoabs.BytesKey(conflictedCountKey))
		if err != nil {
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
		if err != nil {
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
		for i, keyTx := range metadata.SourceTransactions {
			if keyTx.Equals(*resolveMetadata.SourceTransaction) {
				break
			}
			if i == len(metadata.SourceTransactions)-1 {
				return false
			}
		}
	}

	return true
}
