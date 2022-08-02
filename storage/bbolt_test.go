package storage

import (
	"context"
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/go-stoabs/bbolt"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"path"
	"testing"
	"time"
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

		if !assert.NoError(t, err) {
			return
		}
		backupFile := path.Join(backupDir, fullStoreName+bboltDbExtension)
		if !assert.FileExists(t, backupFile) {
			return
		}

		// Close the store, reopen backup
		_ = store.Close(context.Background())
		store, err = bbolt.CreateBBoltStore(backupFile)
		if !assert.NoError(t, err) {
			return
		}
		// Read value and compare
		var actualValue []byte
		err = store.ReadShelf(ctx, "data", func(reader stoabs.Reader) error {
			actualValue, _ = reader.Get(key)
			return nil
		})
		if !assert.NoError(t, err) {
			return
		}
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
		err := store.ReadShelf(ctx, "data", func(reader stoabs.Reader) error {
			actualValue, _ = reader.Get(key)
			return nil
		})
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, newValue, actualValue)
	})
}

func Test_bboltDatabase_startBackup(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	datadir := io.TestDirectory(t)
	backupDir := path.Join(datadir, "backups")
	db, _ := createBBoltDatabase(datadir, BBoltConfig{BBoltBackupConfig{
		Directory: backupDir,
		Interval:  time.Second,
	}})

	t.Run("scheduled backup is performed", func(t *testing.T) {
		store, _ := db.createStore(moduleName, storeName)
		defer store.Close(context.Background())

		_ = store.WriteShelf(context.Background(), "data", func(writer stoabs.Writer) error {
			return writer.Put(key, value)
		})

		// Wait for backup to be performed, then close database (which allows running backup procedures to finish)
		time.Sleep(time.Second)
		db.close()

		db.shutdownWatcher.Wait()
		assert.FileExists(t, path.Join(backupDir, fullStoreName+bboltDbExtension))
	})
}

func Test_bboltDatabase_getClass(t *testing.T) {
	assert.Equal(t, VolatileStorageClass, bboltDatabase{}.getClass())
}
