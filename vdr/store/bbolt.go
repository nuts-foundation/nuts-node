/*
 * Nuts node
 * Copyright (C) 2021 Nuts community
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

package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/storage"
	vdr "github.com/nuts-foundation/nuts-node/vdr/types"
)

const (
	// latestShelf has DID as key and latest metadata reference as value
	latestShelf = "latest"
	// metadataShelf has the metadata reference (DID concatenated with version number, starting at 0) as key and the metadataRecord as value
	metadataShelf = "metadata"
	// transactionIndexShelf has the transaction reference as key and metadata reference as value
	transactionIndexShelf = "txRef"
	// documentShelf has payload hash as key and document as value
	documentShelf = "documents"
	// didStoreName contains the name for the store
	didStoreName = "didstore"
)

type store struct {
	db            stoabs.KVStore
	storeProvider storage.Provider
}

func (s *store) Name() string {
	return "DID Document Store"
}

// NewStore returns an instance of a VDR store
func NewStore(storeProvider storage.Provider) vdr.Store {
	return &store{storeProvider: storeProvider}
}

func (s *store) Configure(_ core.ServerConfig) error {
	var err error
	s.db, err = s.storeProvider.GetKVStore(didStoreName, storage.PersistentStorageClass)
	if err != nil {
		return err
	}
	// shelfs must be initialized here for boot order
	return storage.InitializeShelfs(s.db, latestShelf, metadataShelf, transactionIndexShelf, documentShelf)
}

func (s *store) Start() error {
	return nil
}

func (s *store) Shutdown() error {
	if s.db != nil {
		return s.db.Close(context.Background())
	}
	return nil
}

type metadataRecord struct {
	Deactivated bool                 `json:"deactivated"`
	DID         string               `json:"did"`
	Version     int                  `json:"version"`
	Metadata    vdr.DocumentMetadata `json:"metadata"`
	// PrevRecord holds the previous metadataRecord reference (DID + version) as string
	PrevMetaRef []byte `json:"prevMetaRef"`
}

func (mr metadataRecord) ref() []byte {
	metaRefString := fmt.Sprintf("%s%d", mr.DID, mr.Version)
	return []byte(metaRefString)
}

func (s *store) Write(document did.Document, metadata vdr.DocumentMetadata) error {
	return s.db.Write(func(tx stoabs.WriteTx) error {
		latestWriter, err := tx.GetShelfWriter(latestShelf)
		if err != nil {
			return err
		}

		didString := document.ID.String()

		// first get latest
		latestBytes, err := latestWriter.Get(stoabs.BytesKey(didString))
		if err != nil {
			return nil
		}
		if latestBytes != nil {
			return vdr.ErrDIDAlreadyExists
		}

		// add new metadata record pointing to latest
		newMetadataRecord := metadataRecord{
			Deactivated: IsDeactivated(document),
			DID:         document.ID.String(),
			Metadata:    metadata,
			Version:     0,
		}

		return s.writeDocument(tx, document, newMetadataRecord)
	})
}

func (s *store) Update(id did.DID, current hash.SHA256Hash, next did.Document, metadata *vdr.DocumentMetadata) error {
	return s.db.Write(func(tx stoabs.WriteTx) error {
		latestWriter, err := tx.GetShelfWriter(latestShelf)
		if err != nil {
			return err
		}
		metadataWriter, err := tx.GetShelfWriter(metadataShelf)
		if err != nil {
			return err
		}
		didString := id.String()

		// first get latest
		var version int
		var prevMetaRef []byte
		latestRef, err := latestWriter.Get(stoabs.BytesKey(didString))
		if err != nil {
			return err
		}

		// check for existence
		if latestRef == nil {
			return vdr.ErrNotFound
		}

		latestBytes, err := metadataWriter.Get(stoabs.BytesKey(latestRef))
		if err != nil {
			return err
		}
		latestMetadata := metadataRecord{}
		if err := json.Unmarshal(latestBytes, &latestMetadata); err != nil {
			return err
		}

		// check for hash
		if !current.Equals(latestMetadata.Metadata.Hash) {
			return vdr.ErrUpdateOnOutdatedData
		}

		// add new metadata record pointing to latest
		prevMetaRef = latestMetadata.ref()
		version = latestMetadata.Version + 1
		newMetadataRecord := metadataRecord{
			Deactivated: IsDeactivated(next),
			DID:         didString,
			Metadata:    *metadata,
			PrevMetaRef: prevMetaRef,
			Version:     version,
		}

		return s.writeDocument(tx, next, newMetadataRecord)
	})
}

func (s *store) writeDocument(tx stoabs.WriteTx, document did.Document, metadataRecord metadataRecord) error {
	// get shelf writers
	latestWriter, err := tx.GetShelfWriter(latestShelf)
	if err != nil {
		return err
	}
	metadataWriter, err := tx.GetShelfWriter(metadataShelf)
	if err != nil {
		return err
	}
	transactionIndexWriter, err := tx.GetShelfWriter(transactionIndexShelf)
	if err != nil {
		return err
	}
	documentWriter, err := tx.GetShelfWriter(documentShelf)
	if err != nil {
		return err
	}

	// store in metadataShelf
	newRefBytes := metadataRecord.ref()
	newRecordBytes, _ := json.Marshal(metadataRecord)
	if err := metadataWriter.Put(stoabs.BytesKey(newRefBytes), newRecordBytes); err != nil {
		return err
	}

	// update latestShelf
	if err := latestWriter.Put(stoabs.BytesKey(metadataRecord.DID), newRefBytes); err != nil {
		return err
	}

	// update transactionIndex, this may overwrite entries in case of a conflict, but that's ok
	for _, sourceTX := range metadataRecord.Metadata.SourceTransactions {
		if err := transactionIndexWriter.Put(stoabs.NewHashKey(sourceTX), newRefBytes); err != nil {
			return err
		}
	}

	// add payload to documentShelf
	documentBytes, _ := json.Marshal(document)
	return documentWriter.Put(stoabs.NewHashKey(metadataRecord.Metadata.Hash), documentBytes)
}

func (s *store) Processed(hash hash.SHA256Hash) (processed bool, txErr error) {
	txErr = s.db.Read(func(tx stoabs.ReadTx) error {
		transactionIndexReader := tx.GetShelfReader(transactionIndexShelf)

		ref, err := transactionIndexReader.Get(stoabs.NewHashKey(hash))
		if err != nil {
			return err
		}
		if ref != nil {
			processed = true
		}
		return nil
	})

	return
}

// Iterate loops over all the latest versions of the stored DID Documents and applies fn
func (s *store) Iterate(fn vdr.DocIterator) error {
	return s.db.Read(func(tx stoabs.ReadTx) error {
		// get shelf readers
		latestReader := tx.GetShelfReader(latestShelf)
		metadataReader := tx.GetShelfReader(metadataShelf)
		documentReader := tx.GetShelfReader(documentShelf)

		return latestReader.Iterate(func(didKey stoabs.Key, metadataRecordRef []byte) error {
			metadataRecordBytes, err := metadataReader.Get(stoabs.BytesKey(metadataRecordRef))
			if err != nil {
				return err
			}
			var metadataRecord metadataRecord
			if err := json.Unmarshal(metadataRecordBytes, &metadataRecord); err != nil {
				return err
			}
			documentBytes, err := documentReader.Get(stoabs.NewHashKey(metadataRecord.Metadata.Hash))
			if err != nil {
				return err
			}
			var document did.Document
			if err := json.Unmarshal(documentBytes, &document); err != nil {
				return err
			}

			return fn(document, metadataRecord.Metadata)
		})
	})
}

func (s *store) Resolve(id did.DID, metadata *vdr.ResolveMetadata) (returnDocument *did.Document, returnMetadata *vdr.DocumentMetadata, txErr error) {
	txErr = s.db.Read(func(tx stoabs.ReadTx) error {
		// get shelf readers
		latestReader := tx.GetShelfReader(latestShelf)
		latestRefBytes, _ := latestReader.Get(stoabs.BytesKey(id.String()))
		if latestRefBytes == nil {
			return vdr.ErrNotFound
		}
		latestMetadataRef := latestRefBytes

		metadataReader := tx.GetShelfReader(metadataShelf)
		documentReader := tx.GetShelfReader(documentShelf)

		// loop over all versions
		for latestMetadataRef != nil {
			var metadataRecord metadataRecord
			metadataBytes, err := metadataReader.Get(stoabs.BytesKey(latestMetadataRef))
			if err != nil {
				return err
			}
			if err := json.Unmarshal(metadataBytes, &metadataRecord); err != nil {
				return err
			}

			if matches(metadataRecord, metadata) {
				returnMetadata = &metadataRecord.Metadata
				docBytes, err := documentReader.Get(stoabs.NewHashKey(metadataRecord.Metadata.Hash))
				if err != nil {
					return err
				}
				var document did.Document
				if err := json.Unmarshal(docBytes, &document); err != nil {
					return err
				}
				returnDocument = &document
				return nil
			}

			latestMetadataRef = metadataRecord.PrevMetaRef
		}
		return vdr.ErrNotFound
	})
	return
}

func matches(metadataRecord metadataRecord, metadata *vdr.ResolveMetadata) bool {
	if metadataRecord.Deactivated && (metadata == nil || !metadata.AllowDeactivated) {
		return false
	}

	if metadata == nil {
		return true
	}

	// Filter on hash
	if metadata.Hash != nil && !metadataRecord.Metadata.Hash.Equals(*metadata.Hash) {
		return false
	}

	// Filter on creation and update time
	if metadata.ResolveTime != nil {
		resolveTime := *metadata.ResolveTime

		if metadataRecord.Metadata.Updated != nil {
			if metadataRecord.Metadata.Updated.After(resolveTime) {
				return false
			}
		}

		if metadataRecord.Metadata.Created.After(resolveTime) {
			return false
		}
	}

	// Filter on SourceTransaction
	if metadata.SourceTransaction != nil {
		for i, keyTx := range metadataRecord.Metadata.SourceTransactions {
			if keyTx.Equals(*metadata.SourceTransaction) {
				break
			}
			if i == len(metadataRecord.Metadata.SourceTransactions)-1 {
				return false
			}
		}
	}

	return true
}
