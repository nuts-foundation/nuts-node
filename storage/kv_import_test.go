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
	"fmt"
	"os"
	"testing"

	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/nuts-node/v6/core"
	"github.com/nuts-foundation/nuts-node/v6/test/io"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeBBoltFixture starts a bbolt-backed engine in dir, writes rows to the given store shelves and shuts it down.
// rows per shelf: "k<i>" -> "v<i>" for i in [0, count).
func writeBBoltFixture(t *testing.T, dir string, module string, store string, shelves []string, count int) {
	ctx := context.Background()
	e := NewTestStorageEngineInDir(t, dir)
	kv, err := e.GetProvider(module).GetKVStore(store, PersistentStorageClass)
	require.NoError(t, err)
	for _, shelf := range shelves {
		require.NoError(t, kv.WriteShelf(ctx, shelf, func(writer stoabs.Writer) error {
			for i := 0; i < count; i++ {
				if err := writer.Put(stoabs.BytesKey(fmt.Sprintf("k%d", i)), []byte(fmt.Sprintf("v%d", i))); err != nil {
					return err
				}
			}
			return nil
		}))
	}
	require.NoError(t, e.Shutdown())
}

func countShelf(t *testing.T, e Engine, module string, store string, shelf string) int {
	kv, err := e.GetProvider(module).GetKVStore(store, PersistentStorageClass)
	require.NoError(t, err)
	count := 0
	require.NoError(t, kv.ReadShelf(context.Background(), shelf, func(reader stoabs.Reader) error {
		return reader.Iterate(func(_ stoabs.Key, _ []byte) error {
			count++
			return nil
		}, stoabs.BytesKey{})
	}))
	return count
}

func TestImportBBoltStores(t *testing.T) {
	const rows = 2*kvImportBatchSize + 7 // more than one batch, uneven

	t.Run("imports all stores, renames the files, idempotent on restart", func(t *testing.T) {
		dir := io.TestDirectory(t)
		writeBBoltFixture(t, dir, "Network", "data", []string{"documents", "clocks", "_vdr_jobs"}, rows)
		writeBBoltFixture(t, dir, "VDR", "didstore", []string{"latestV2", "documentsV2"}, 3)
		dataDir := dir + "/data"
		require.FileExists(t, bboltFilePath(dataDir, "network", "data"))
		require.FileExists(t, bboltFilePath(dataDir, "vdr", "didstore"))

		e := NewTestStorageEngineSQLKVInDir(t, dir)
		assert.Equal(t, rows, countShelf(t, e, "Network", "data", "documents"))
		assert.Equal(t, rows, countShelf(t, e, "Network", "data", "clocks"))
		assert.Equal(t, rows, countShelf(t, e, "Network", "data", "_vdr_jobs"))
		assert.Equal(t, 0, countShelf(t, e, "Network", "data", "payloads"))
		assert.Equal(t, 3, countShelf(t, e, "VDR", "didstore", "latestV2"))
		// values survived
		kv, err := e.GetProvider("Network").GetKVStore("data", PersistentStorageClass)
		require.NoError(t, err)
		var value []byte
		require.NoError(t, kv.ReadShelf(context.Background(), "documents", func(reader stoabs.Reader) error {
			var err error
			value, err = reader.Get(stoabs.BytesKey("k1500"))
			return err
		}))
		assert.Equal(t, []byte("v1500"), value)
		// files renamed
		assert.NoFileExists(t, bboltFilePath(dataDir, "network", "data"))
		assert.FileExists(t, bboltFilePath(dataDir, "network", "data")+kvMigratedSuffix)
		assert.FileExists(t, bboltFilePath(dataDir, "vdr", "didstore")+kvMigratedSuffix)
		require.NoError(t, e.Shutdown())

		// second start on sql: nothing to import, data still there
		e2 := NewTestStorageEngineSQLKVInDir(t, dir)
		assert.Equal(t, rows, countShelf(t, e2, "Network", "data", "documents"))
	})
	t.Run("no bbolt files: nothing happens", func(t *testing.T) {
		e := NewTestStorageEngineSQLKV(t)
		assert.Equal(t, 0, countShelf(t, e, "Network", "data", "documents"))
	})
	t.Run("refuses when both bbolt file and SQL data exist", func(t *testing.T) {
		dir := io.TestDirectory(t)
		// first run on sql writes data
		e := NewTestStorageEngineSQLKVInDir(t, dir)
		kv, err := e.GetProvider("Network").GetKVStore("data", PersistentStorageClass)
		require.NoError(t, err)
		require.NoError(t, kv.WriteShelf(context.Background(), "documents", func(writer stoabs.Writer) error {
			return writer.Put(stoabs.BytesKey("sql"), []byte("1"))
		}))
		require.NoError(t, e.Shutdown())
		// then a bbolt file appears (e.g. the operator ran on bbolt in between)
		writeBBoltFixture(t, dir, "Network", "data", []string{"documents"}, 1)

		again := New().(*engine)
		again.config = DefaultConfig()
		again.sqlMigrationLogger = nilGooseLogger{}
		again.config.SQL = SQLConfig{ConnectionString: sqliteConnectionString(dir)}
		again.config.KV.Backend = KVBackendSQL
		err = again.Configure(core.TestServerConfig(func(config *core.ServerConfig) {
			config.Datadir = dir + "/data"
		}))
		require.Error(t, err)
		assert.ErrorContains(t, err, "import of bbolt store network/data into SQL failed")
		assert.ErrorContains(t, err, "both the bbolt file")
		// bbolt file untouched
		assert.FileExists(t, bboltFilePath(dir+"/data", "network", "data"))
	})
	t.Run("refuses an unknown bucket and leaves no partial data", func(t *testing.T) {
		dir := io.TestDirectory(t)
		writeBBoltFixture(t, dir, "Network", "data", []string{"documents", "not-a-shelf"}, 5)

		again := New().(*engine)
		again.config = DefaultConfig()
		again.sqlMigrationLogger = nilGooseLogger{}
		again.config.SQL = SQLConfig{ConnectionString: sqliteConnectionString(dir)}
		again.config.KV.Backend = KVBackendSQL
		err := again.Configure(core.TestServerConfig(func(config *core.ServerConfig) {
			config.Datadir = dir + "/data"
		}))
		require.Error(t, err)
		assert.ErrorContains(t, err, `bucket "not-a-shelf" which is not a known shelf`)
		assert.FileExists(t, bboltFilePath(dir+"/data", "network", "data"))
		// "documents" was iterated before "not-a-shelf" (bucket order is bytewise: "_" < "d" < "n"),
		// its rows must have been removed again
		sqlOnly := New().(*engine)
		sqlOnly.config = DefaultConfig()
		sqlOnly.sqlMigrationLogger = nilGooseLogger{}
		sqlOnly.config.SQL = SQLConfig{ConnectionString: sqliteConnectionString(dir)}
		sqlOnly.config.KV.Backend = KVBackendSQL
		require.NoError(t, os.Rename(bboltFilePath(dir+"/data", "network", "data"), bboltFilePath(dir+"/data", "network", "data")+".aside"))
		require.NoError(t, sqlOnly.Configure(core.TestServerConfig(func(config *core.ServerConfig) {
			config.Datadir = dir + "/data"
		})))
		t.Cleanup(func() { _ = sqlOnly.Shutdown() })
		assert.Equal(t, 0, countShelf(t, sqlOnly, "Network", "data", "documents"))
	})
}
