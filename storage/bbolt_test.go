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
	"os"
	"path"
	"testing"
	"time"

	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/go-stoabs/bbolt"
	"github.com/nuts-foundation/nuts-node/test"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const moduleName = "test"
const storeName = "store"
const fullStoreName = moduleName + "/" + storeName

var key = stoabs.BytesKey{1, 2, 3}
var value = []byte{4, 5, 6}

func Test_bboltDatabase_performBackup(t *testing.T) {
	ctx := context.Background()
	datadir := io.TestDirectory(t)
	backupDir := path.Join(datadir, "backups")
	db, _ := createBBoltDatabase(datadir, BBoltConfig{BBoltBackupConfig{
		Directory: backupDir,
		// Not specifying interval: disables scheduled backup
	}})

	t.Run("write some data, then backup, then assert the entry can be read", func(t *testing.T) {
		store, _ := db.createStore(moduleName, storeName)
		defer store.Close(ctx)

		_ = store.WriteShelf(ctx, "data", func(writer stoabs.Writer) error {
			return writer.Put(key, value)
		})

		err := db.performBackup(fullStoreName, store)

		require.NoError(t, err)
		backupFile := path.Join(backupDir, fullStoreName+bboltDbExtension)
		require.FileExists(t, backupFile)

		// Close the store, reopen backup
		_ = store.Close(context.Background())
		store, err = bbolt.CreateBBoltStore(backupFile)
		require.NoError(t, err)
		// Read value and compare
		var actualValue []byte
		err = store.ReadShelf(ctx, "data", func(reader stoabs.Reader) error {
			var err error
			actualValue, err = reader.Get(key)
			return err
		})
		require.NoError(t, err)
		assert.Equal(t, value, actualValue)
	})

	t.Run("subsequent backups", func(t *testing.T) {
		store, _ := db.createStore(moduleName, storeName)
		defer store.Close(context.Background())

		var newValue = []byte{10, 11, 12}

		// Write data, then backup, then overwrite the value and backup again. Check that the backup contains the most recent data.
		_ = store.WriteShelf(ctx, "data", func(writer stoabs.Writer) error {
			return writer.Put(key, value)
		})
		_ = db.performBackup(fullStoreName, store)

		_ = store.WriteShelf(ctx, "data", func(writer stoabs.Writer) error {
			return writer.Put(key, newValue)
		})
		_ = db.performBackup(fullStoreName, store)

		// Close the store, reopen backup
		backupFile := path.Join(backupDir, fullStoreName+bboltDbExtension)
		_ = store.Close(context.Background())
		store, _ = bbolt.CreateBBoltStore(backupFile)

		// Read value and compare
		var actualValue []byte
		txErr := store.ReadShelf(ctx, "data", func(reader stoabs.Reader) error {
			var err error
			actualValue, err = reader.Get(key)
			return err
		})
		require.NoError(t, txErr)
		assert.Equal(t, newValue, actualValue)
	})
}

func Test_bboltDatabase_startBackup(t *testing.T) {
	t.Run("scheduled backup is performed", func(t *testing.T) {
		logrus.SetLevel(logrus.DebugLevel)
		datadir := io.TestDirectory(t)
		backupDir := path.Join(datadir, "backups")
		db, _ := createBBoltDatabase(datadir, BBoltConfig{Backup: BBoltBackupConfig{
			Directory: backupDir,
			Interval:  100 * time.Millisecond,
		}})

		store, _ := db.createStore(moduleName, storeName)
		defer store.Close(context.Background())

		_ = store.WriteShelf(context.Background(), "data", func(writer stoabs.Writer) error {
			return writer.Put(key, value)
		})

		// Wait for backup to be performed, then close database (which allows running backup procedures to finish)
		test.WaitFor(t, func() (bool, error) {
			if _, err := os.Stat(path.Join(backupDir, fullStoreName+bboltDbExtension)); errors.Is(err, os.ErrNotExist) {
				// File does not exist
				return false, nil
			} else if err != nil {
				// Other error occurred
				return false, err
			} else {
				// File exists
				return true, nil
			}
		}, 5*time.Second, "time-out while waiting for backup to be written")
	})
}

func Test_bboltDatabase_getClass(t *testing.T) {
	assert.Equal(t, VolatileStorageClass, bboltDatabase{}.getClass())
}
