/*
 * Copyright (C) 2026 Nuts community
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
	"os"
	"path"
	"time"

	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/nuts-node/v6/core"
	"github.com/nuts-foundation/nuts-node/v6/storage/log"
	"github.com/nuts-foundation/nuts-node/v6/storage/sql_migrations"
	bboltLib "go.etcd.io/bbolt"
)

// kvImportBatchSize is the number of key/value pairs written per SQL transaction during the bbolt import.
const kvImportBatchSize = 1000

// kvMigratedSuffix is appended to a bbolt file after its contents were imported into SQL.
const kvMigratedSuffix = ".migrated"

// importBBoltStores imports the bbolt files of the did:nuts KV stores into the SQL KV database, for stores whose
// bbolt file exists in the data directory. It runs when storage.kv.backend is switched to sql on a node that has
// bbolt data. Per store:
//
//   - The SQL tables of the store must be empty, otherwise it refuses: both a bbolt file and SQL data exist and it
//     is unclear which is current. The operator removes or renames one.
//   - Every bucket in the file must be a known shelf of the store, otherwise it refuses: an unknown bucket would be
//     silently dropped.
//   - On success the file is renamed to "<name>.db.migrated". On failure the rows written for that store are
//     removed again and the file is left untouched, so the node can be started on bbolt again.
func importBBoltStores(datadir string, kvDB *sqlKVDatabase) error {
	for _, store := range sql_migrations.KVStores() {
		filePath := bboltFilePath(datadir, store.Module, store.Store)
		if _, err := os.Stat(filePath); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return err
		}
		if err := importBBoltStore(filePath, store.Module, store.Store, kvDB); err != nil {
			return fmt.Errorf("import of bbolt store %s/%s into SQL failed: %w", store.Module, store.Store, err)
		}
	}
	return nil
}

func bboltFilePath(datadir string, moduleName string, storeName string) string {
	return path.Join(datadir, moduleName, storeName) + bboltDbExtension
}

func importBBoltStore(filePath string, moduleName string, storeName string, kvDB *sqlKVDatabase) error {
	ctx := context.Background()
	logger := log.Logger().WithField(core.LogFieldStore, path.Join(moduleName, storeName))
	shelves := make(map[string]bool)
	for _, shelf := range sql_migrations.KVShelves {
		if shelf.Module == moduleName && shelf.Store == storeName {
			shelves[shelf.Shelf] = true
		}
	}

	target, err := kvDB.createStore(moduleName, storeName)
	if err != nil {
		return err
	}
	defer func() { _ = target.Close(ctx) }()

	// Refuse when SQL already holds data for this store
	for shelf := range shelves {
		var empty bool
		err := target.ReadShelf(ctx, shelf, func(reader stoabs.Reader) error {
			var err error
			empty, err = reader.Empty()
			return err
		})
		if err != nil {
			return err
		}
		if !empty {
			return fmt.Errorf("both the bbolt file (%s) and SQL data exist for this store; remove or rename one of them", filePath)
		}
	}

	source, err := bboltLib.Open(filePath, 0400, &bboltLib.Options{ReadOnly: true, Timeout: 10 * time.Second})
	if err != nil {
		return fmt.Errorf("unable to open bbolt file %s (is another node instance still using it?): %w", filePath, err)
	}
	defer func() { _ = source.Close() }()

	logger.Infof("Importing bbolt file %s into SQL...", filePath)
	start := time.Now()
	totalRows := 0
	err = source.View(func(tx *bboltLib.Tx) error {
		return tx.ForEach(func(name []byte, bucket *bboltLib.Bucket) error {
			shelf := string(name)
			if !shelves[shelf] {
				return fmt.Errorf("bbolt file contains bucket %q which is not a known shelf of this store", shelf)
			}
			rows, err := importBucket(ctx, target, shelf, bucket)
			totalRows += rows
			return err
		})
	})
	if err != nil {
		// Leave no partial state behind: remove whatever was written for this store
		for shelf := range shelves {
			if cleanupErr := clearShelf(ctx, target, shelf); cleanupErr != nil {
				logger.WithError(cleanupErr).Errorf("Could not remove partially imported rows from shelf %s", shelf)
			}
		}
		return err
	}
	if err := source.Close(); err != nil {
		return err
	}
	if err := os.Rename(filePath, filePath+kvMigratedSuffix); err != nil {
		return fmt.Errorf("imported into SQL, but unable to rename bbolt file %s: %w", filePath, err)
	}
	logger.Infof("Imported %d entries from bbolt into SQL in %s, renamed file to %s", totalRows, time.Since(start).Round(time.Millisecond), filePath+kvMigratedSuffix)
	return nil
}

func importBucket(ctx context.Context, target stoabs.KVStore, shelf string, bucket *bboltLib.Bucket) (int, error) {
	type entry struct{ key, value []byte }
	var batch []entry
	rows := 0
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		err := target.WriteShelf(ctx, shelf, func(writer stoabs.Writer) error {
			for _, e := range batch {
				if err := writer.Put(stoabs.BytesKey(e.key), e.value); err != nil {
					return err
				}
			}
			return nil
		})
		batch = batch[:0]
		return err
	}
	err := bucket.ForEach(func(k, v []byte) error {
		if v == nil {
			// nested bucket; the Nuts node does not use those
			return fmt.Errorf("unexpected nested bucket %q in shelf %s", k, shelf)
		}
		// bbolt's slices are only valid inside the transaction, copy them
		batch = append(batch, entry{key: append([]byte{}, k...), value: append([]byte{}, v...)})
		rows++
		if len(batch) >= kvImportBatchSize {
			return flush()
		}
		return nil
	})
	if err != nil {
		return rows, err
	}
	return rows, flush()
}

func clearShelf(ctx context.Context, target stoabs.KVStore, shelf string) error {
	var keys []stoabs.Key
	err := target.ReadShelf(ctx, shelf, func(reader stoabs.Reader) error {
		return reader.Iterate(func(key stoabs.Key, _ []byte) error {
			keys = append(keys, key)
			return nil
		}, stoabs.BytesKey{})
	})
	if err != nil {
		return err
	}
	for start := 0; start < len(keys); start += kvImportBatchSize {
		end := min(start+kvImportBatchSize, len(keys))
		err := target.WriteShelf(ctx, shelf, func(writer stoabs.Writer) error {
			for _, key := range keys[start:end] {
				if err := writer.Delete(key); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}
