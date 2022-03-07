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
	"fmt"
	"os"
	"path"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"go.etcd.io/bbolt"

	vdr "github.com/nuts-foundation/nuts-node/vdr/types"
)

const (
	// latestBucket has did as key and latest metadata reference as value
	latestBucket = "latest"
	// metadataBucket has the metadata reference (did concatenated with version number, starting at 0) as key and the metadataRecord as value
	metadataBucket = "metadata"
	// transactionIndexBucket has the transaction reference as key and metadata reference as value
	transactionIndexBucket = "txRef"
	// documentsBucket has payload hash as key and document as value
	documentBucket = "documents"
)

type bboltStore struct {
	db *bbolt.DB
}

// NewBBoltStore returns an instance of a BBolt based VDR store
func NewBBoltStore() vdr.Store {
	return &bboltStore{}
}

func (store *bboltStore) Configure(config core.ServerConfig) error {
	var err error
	filePath := path.Join(config.Datadir, "vdr", "didstore.db")
	if err = os.MkdirAll(path.Join(config.Datadir, "vdr"), os.ModePerm); err != nil {
		return err
	}
	store.db, err = bbolt.Open(filePath, 0600, bbolt.DefaultOptions)

	return err
}

func (store *bboltStore) Start() error {
	// already done in Configure
	return nil
}

func (store *bboltStore) Shutdown() error {
	if store.db != nil {
		return store.db.Close()
	}
	return nil
}

type metadataRecord struct {
	Deactivated bool `json:"deactivated"`
	DID         string
	Version     int `json:"version"`
	Metadata    vdr.DocumentMetadata
	// PrevRecord holds the previous metadataRecord reference (DID + version) as string
	PrevMetaRef []byte `json:"prevMetaRef"`
}

func (mr metadataRecord) ref() []byte {
	metaRefString := fmt.Sprintf("%s%06d", mr.DID, mr.Version)
	return []byte(metaRefString)
}

func (store *bboltStore) Write(document did.Document, metadata vdr.DocumentMetadata) error {
	return store.db.Update(func(tx *bbolt.Tx) error {
		if err := store.createBucketsIfNotExist(tx); err != nil {
			return err
		}

		latestBucket := tx.Bucket([]byte(latestBucket))
		didString := document.ID.String()

		// first get latest
		latestBytes := latestBucket.Get([]byte(didString))
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

		return store.writeDocument(tx, document, newMetadataRecord)
	})
}

func (store *bboltStore) Update(id did.DID, current hash.SHA256Hash, next did.Document, metadata *vdr.DocumentMetadata) error {
	return store.db.Update(func(tx *bbolt.Tx) error {
		latestBucket := tx.Bucket([]byte(latestBucket))
		metadataBucket := tx.Bucket([]byte(metadataBucket))
		didString := id.String()

		// first get latest
		var version int
		var prevMetaRef []byte
		latestRef := latestBucket.Get([]byte(didString))

		// check for existence
		if latestRef == nil {
			return vdr.ErrNotFound
		}

		latestBytes := metadataBucket.Get(latestRef)
		latestMetadata := metadataRecord{}
		if err := json.Unmarshal(latestBytes, &latestMetadata); err != nil {
			return err
		}

		// check for deactivated
		if latestMetadata.Deactivated {
			return vdr.ErrDeactivated
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

		return store.writeDocument(tx, next, newMetadataRecord)
	})
}

func (store *bboltStore) writeDocument(tx *bbolt.Tx, document did.Document, metadataRecord metadataRecord) error {

	latestBucket := tx.Bucket([]byte(latestBucket))
	metadataBucket := tx.Bucket([]byte(metadataBucket))
	transactionIndex := tx.Bucket([]byte(transactionIndexBucket))
	documentBucket := tx.Bucket([]byte(documentBucket))

	// store in metadataBucket
	newRefBytes := metadataRecord.ref()
	newRecordBytes, _ := json.Marshal(metadataRecord)
	if err := metadataBucket.Put(newRefBytes, newRecordBytes); err != nil {
		return err
	}

	// update latestBucket
	if err := latestBucket.Put([]byte(metadataRecord.DID), newRefBytes); err != nil {
		return err
	}

	// update transactionIndex, this may overwrite entries in case of a conflict, but that's ok
	for _, sourceTX := range metadataRecord.Metadata.SourceTransactions {
		if err := transactionIndex.Put(sourceTX.Slice(), newRefBytes); err != nil {
			return err
		}
	}

	// add payload to documentBucket
	documentBytes, _ := json.Marshal(document)
	return documentBucket.Put(metadataRecord.Metadata.Hash.Slice(), documentBytes)
}

func (store *bboltStore) Processed(hash hash.SHA256Hash) (processed bool, txErr error) {
	txErr = store.db.View(func(tx *bbolt.Tx) error {
		transactionIndexBucket := tx.Bucket([]byte(transactionIndexBucket))
		if transactionIndexBucket == nil {
			return nil
		}

		ref := transactionIndexBucket.Get(hash.Slice())
		if ref != nil {
			processed = true
		}
		return nil
	})

	return
}

func (store *bboltStore) createBucketsIfNotExist(tx *bbolt.Tx) error {
	if _, err := tx.CreateBucketIfNotExists([]byte(latestBucket)); err != nil {
		return err
	}
	if _, err := tx.CreateBucketIfNotExists([]byte(metadataBucket)); err != nil {
		return err
	}
	if _, err := tx.CreateBucketIfNotExists([]byte(transactionIndexBucket)); err != nil {
		return err
	}
	_, err := tx.CreateBucketIfNotExists([]byte(documentBucket))
	return err
}

// Iterate loops over all the latest versions of the stored DID Documents and applies fn
func (store *bboltStore) Iterate(fn vdr.DocIterator) error {
	return store.db.View(func(tx *bbolt.Tx) error {
		latestBucket := tx.Bucket([]byte(latestBucket))
		if latestBucket == nil {
			return nil
		}

		metadataBucket := tx.Bucket([]byte(metadataBucket))
		documentBucket := tx.Bucket([]byte(documentBucket))

		return latestBucket.ForEach(func(didKey, metadataRecordRef []byte) error {
			metadataRecordBytes := metadataBucket.Get(metadataRecordRef)
			var metadataRecord metadataRecord
			if err := json.Unmarshal(metadataRecordBytes, &metadataRecord); err != nil {
				return err
			}
			documentBytes := documentBucket.Get(metadataRecord.Metadata.Hash.Slice())
			var document did.Document
			if err := json.Unmarshal(documentBytes, &document); err != nil {
				return err
			}

			return fn(document, metadataRecord.Metadata)
		})
	})
}

func (store *bboltStore) Resolve(id did.DID, metadata *vdr.ResolveMetadata) (returnDocument *did.Document, returnMetadata *vdr.DocumentMetadata, txErr error) {
	txErr = store.db.View(func(tx *bbolt.Tx) error {
		// we start at the latest version
		latestBucket := tx.Bucket([]byte(latestBucket))
		if latestBucket == nil {
			return vdr.ErrNotFound
		}

		metadataBucket := tx.Bucket([]byte(metadataBucket))
		latestRefBytes := latestBucket.Get([]byte(id.String()))
		if latestRefBytes == nil {
			return vdr.ErrNotFound
		}
		latestMetadataRef := latestRefBytes
		documentBucket := tx.Bucket([]byte(documentBucket))

		// loop over all versions
		var metadataRecord metadataRecord
		for latestMetadataRef != nil {
			metadataBytes := metadataBucket.Get(latestMetadataRef)
			if err := json.Unmarshal(metadataBytes, &metadataRecord); err != nil {
				return err
			}

			if matches(metadataRecord, metadata) {
				returnMetadata = &metadataRecord.Metadata
				docBytes := documentBucket.Get(metadataRecord.Metadata.Hash.Slice())
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

		if metadataRecord.Metadata.Created.After(resolveTime) {
			return false
		}

		if metadataRecord.Metadata.Updated != nil {
			if metadataRecord.Metadata.Updated.After(resolveTime) {
				return false
			}
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
