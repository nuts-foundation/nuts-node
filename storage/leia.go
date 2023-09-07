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

package storage

import (
	"context"
	"errors"
	"fmt"
	"github.com/nuts-foundation/go-leia/v4"
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/storage/log"
)

// KVBackedLeiaStore is a wrapper interface for a leia.Store that uses a stoabs.KVStore as backup for any documents added.
type KVBackedLeiaStore interface {
	leia.Store
	// AddConfiguration adds a configuration for a collection to the store.
	// This is needed to know the kind of collection, the backup shelf name and the iterate query to fetch the documents.
	AddConfiguration(config LeiaBackupConfiguration)
	// HandleRestore migrates the data from the backup store to the leia.Store if needed.
	// It's up to the caller to create the indices on the leia.Collections first before calling this method.
	HandleRestore() error
}

type kvBackedLeiaStore struct {
	store               leia.Store
	backup              stoabs.KVStore
	collectionConfigSet map[string]LeiaBackupConfiguration
}

// NewKVBackedLeiaStore creates a wrapper around a leia.Store that uses a stoabs.KVStore as backup. Write operations (add/delete/update) are first performed on the backup store, then on the leia store.
// The backup store is not closed when Close is called. The leia.Store is closed when Close is called.
func NewKVBackedLeiaStore(store leia.Store, backup stoabs.KVStore) (KVBackedLeiaStore, error) {
	return &kvBackedLeiaStore{
		store:               store,
		backup:              backup,
		collectionConfigSet: map[string]LeiaBackupConfiguration{},
	}, nil
}

// LeiaBackupConfiguration contains the configuration for a collection that is backed by a stoabs.KVStore.
type LeiaBackupConfiguration struct {
	// CollectionName is the name of the collection in the leia.Store.
	CollectionName string
	CollectionType leia.CollectionType
	// BackupShelf is the name of the shelf in the backup store.
	BackupShelf string
	// SearchQuery is used to fill the backup shelf if not present.
	SearchQuery leia.QueryPath
}

type kvBackedCollection struct {
	backup     stoabs.KVStore
	config     LeiaBackupConfiguration
	underlying leia.Collection
}

func (k *kvBackedLeiaStore) AddConfiguration(config LeiaBackupConfiguration) {
	k.collectionConfigSet[config.CollectionName] = config
}

func (k *kvBackedLeiaStore) HandleRestore() error {
	// leia indices have been added, so the collection names have been added to the collectionConfigSet.
	// Loop over this set to check if the backup store contains any documents for these collections and add them to the leia.Store if the named collection is empty there.
	for _, config := range k.collectionConfigSet {
		if err := k.handleRestore(config); err != nil {
			return fmt.Errorf("error handling restore for collection %s: %w", config.CollectionName, err)
		}
	}
	return nil
}

func (k *kvBackedLeiaStore) handleRestore(config LeiaBackupConfiguration) error {
	backupPresent := k.backupStorePresent(config.BackupShelf)
	collection := k.store.Collection(config.CollectionType, config.CollectionName)

	storePresent := storePresent(collection, config)

	if backupPresent && storePresent {
		// both are filled => normal operation, done
		return nil
	}

	if !backupPresent && !storePresent {
		// both are non-existent => empty node, done
		return nil
	}

	if !storePresent {
		log.Logger().
			WithField(core.LogFieldStoreShelf, config.BackupShelf).
			Info("Missing index for shelf, rebuilding")
		// empty node, backup has been restored, refill store
		return k.backup.ReadShelf(context.Background(), config.BackupShelf, func(reader stoabs.Reader) error {
			return reader.Iterate(func(key stoabs.Key, value []byte) error {
				return collection.Add([]leia.Document{value})
			}, stoabs.BytesKey{})
		})
	}

	log.Logger().
		WithField(core.LogFieldStoreShelf, config.BackupShelf).
		Info("Missing store for shelf, creating from index")

	// else !backupPresent, process per 100
	query := leia.New(leia.NotNil(config.SearchQuery))

	const limit = 100
	type refDoc struct {
		ref leia.Reference
		doc leia.Document
	}

	writeDocuments := func(set []refDoc) error {
		return k.backup.Write(context.Background(), func(tx stoabs.WriteTx) error {
			writer := tx.GetShelfWriter(config.BackupShelf)
			for _, entry := range set {
				if err := writer.Put(stoabs.BytesKey(entry.ref), entry.doc); err != nil {
					return err
				}
			}
			return nil
		})
	}

	var set []refDoc
	err := collection.Iterate(query, func(ref leia.Reference, value []byte) error {
		set = append(set, refDoc{ref: ref, doc: value})
		if len(set) >= limit {
			err := writeDocuments(set)
			set = make([]refDoc, 0)
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}

	if len(set) > 0 {
		return writeDocuments(set)
	}
	return nil
}

func (k *kvBackedLeiaStore) Collection(collectionType leia.CollectionType, name string) leia.Collection {
	config, ok := k.collectionConfigSet[name]
	if !ok {
		// we panic here because this is a programming error, not a runtime error
		panic("JSON collection not configured")
	}
	if config.CollectionType != collectionType {
		// we panic here because this is a programming error, not a runtime error
		panic("Incorrect collection configuration")
	}
	underlying := kvBackedCollection{
		backup:     k.backup,
		config:     config,
		underlying: k.store.Collection(collectionType, name),
	}
	return underlying
}

func (k *kvBackedLeiaStore) Close() error {
	return k.store.Close()
}

func (k kvBackedCollection) AddIndex(index ...leia.Index) error {
	return k.underlying.AddIndex(index...)
}

func (k kvBackedCollection) DropIndex(name string) error {
	return k.underlying.DropIndex(name)
}

func (k kvBackedCollection) NewIndex(name string, parts ...leia.FieldIndexer) leia.Index {
	return k.underlying.NewIndex(name, parts...)
}

func (k kvBackedCollection) Add(jsonSet []leia.Document) error {
	// first in backup
	for _, doc := range jsonSet {
		ref := k.Reference(doc)

		if err := k.backup.WriteShelf(context.Background(), k.config.BackupShelf, func(writer stoabs.Writer) error {
			return writer.Put(stoabs.BytesKey(ref), doc)
		}); err != nil {
			return err
		}
	}
	// then in index
	return k.underlying.Add(jsonSet)
}

func (k kvBackedCollection) Get(ref leia.Reference) (leia.Document, error) {
	return k.underlying.Get(ref)
}

func (k kvBackedCollection) Delete(doc leia.Document) error {
	// first in backup
	ref := k.Reference(doc)

	if err := k.backup.WriteShelf(context.Background(), k.config.BackupShelf, func(writer stoabs.Writer) error {
		return writer.Put(stoabs.BytesKey(ref), doc)
	}); err != nil {
		return err
	}
	// then in index
	return k.underlying.Delete(doc)
}

func (k kvBackedCollection) Find(ctx context.Context, query leia.Query) ([]leia.Document, error) {
	return k.underlying.Find(ctx, query)
}

func (k kvBackedCollection) Reference(doc leia.Document) leia.Reference {
	return k.underlying.Reference(doc)
}

func (k kvBackedCollection) Iterate(query leia.Query, walker leia.DocumentWalker) error {
	return k.underlying.Iterate(query, walker)
}

func (k kvBackedCollection) IndexIterate(query leia.Query, fn leia.ReferenceScanFn) error {
	return k.underlying.IndexIterate(query, fn)
}

func (k kvBackedCollection) ValuesAtPath(document leia.Document, queryPath leia.QueryPath) ([]leia.Scalar, error) {
	return k.underlying.ValuesAtPath(document, queryPath)
}

func (k kvBackedCollection) DocumentCount() (int, error) {
	return k.underlying.DocumentCount()
}

func (k *kvBackedLeiaStore) backupStorePresent(backupShelf string) bool {
	backupPresent := false

	_ = k.backup.ReadShelf(context.Background(), backupShelf, func(reader stoabs.Reader) error {
		isEmpty, err := reader.Empty()
		backupPresent = !isEmpty
		return err
	})

	return backupPresent
}

func storePresent(collection leia.Collection, config LeiaBackupConfiguration) bool {
	issuedPresent := false
	query := leia.New(leia.NotNil(config.SearchQuery))
	_ = collection.IndexIterate(query, func(key []byte, value []byte) error {
		issuedPresent = true
		return errors.New("exit")
	})

	return issuedPresent
}
