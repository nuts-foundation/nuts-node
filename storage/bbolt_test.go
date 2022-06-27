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

var key = stoabs.BytesKey{1, 2, 3}
var value = []byte{4, 5, 6}

func Test_bboltDatabase_performBackup(t *testing.T) {
	datadir := io.TestDirectory(t)
	backupDir := path.Join(datadir, "backups")
	db, _ := createBBoltDatabase(datadir, BBoltConfig{BBoltBackupConfig{
		Directory: backupDir,
		// Not specifying interval: disables scheduled backup
	}})

	t.Run("write some data, then backup, then assert the entry can be read", func(t *testing.T) {
		store, _ := db.createStore(moduleName, storeName)
		defer store.Close(context.Background())

		_ = store.WriteShelf("data", func(writer stoabs.Writer) error {
			return writer.Put(key, value)
		})

		err := db.performBackup(moduleName, storeName, store)

		if !assert.NoError(t, err) {
			return
		}
		backupFile := path.Join(backupDir, db.getRelativeStorePath(moduleName, storeName))
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
		err = store.ReadShelf("data", func(reader stoabs.Reader) error {
			actualValue, _ = reader.Get(key)
			return nil
		})
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, value, actualValue)
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

		_ = store.WriteShelf("data", func(writer stoabs.Writer) error {
			return writer.Put(key, value)
		})

		// Wait for backup to be performed, then close database (which allows running backup procedures to finish)
		time.Sleep(time.Second)
		db.close()

		assert.FileExists(t, path.Join(backupDir, db.getRelativeStorePath(moduleName, storeName)))
	})
}
