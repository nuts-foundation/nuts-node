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
	"testing"
	"time"

	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/nuts-node/v6/core"
	"github.com/nuts-foundation/nuts-node/v6/storage/sql_migrations"
	"github.com/nuts-foundation/nuts-node/v6/test/io"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEngine_KVBackendSQL(t *testing.T) {
	ctx := context.Background()

	t.Run("selects the SQL KV database", func(t *testing.T) {
		e := NewTestStorageEngineSQLKV(t).(*engine)
		require.Len(t, e.databases, 1)
		_, ok := e.databases[0].(*sqlKVDatabase)
		assert.True(t, ok)
	})
	t.Run("creates a table per shelf and a seeded lock table per store", func(t *testing.T) {
		e := NewTestStorageEngineSQLKV(t).(*engine)
		for _, shelf := range sql_migrations.KVShelves {
			assert.True(t, e.sqlDB.Migrator().HasTable(shelf.TableName()), shelf.TableName())
		}
		for _, lock := range sql_migrations.KVStores() {
			require.True(t, e.sqlDB.Migrator().HasTable(lock.TableName()), lock.TableName())
			var count int64
			require.NoError(t, e.sqlDB.Table(lock.TableName()).Count(&count).Error)
			assert.Equal(t, int64(1), count, lock.TableName())
		}
	})
	t.Run("write and read through a provider", func(t *testing.T) {
		e := NewTestStorageEngineSQLKV(t)
		store, err := e.GetProvider("Network").GetKVStore("data", PersistentStorageClass)
		require.NoError(t, err)
		key := stoabs.BytesKey("tx_num")
		require.NoError(t, store.WriteShelf(ctx, "metadata", func(writer stoabs.Writer) error {
			return writer.Put(key, []byte{1, 2, 3})
		}))
		var actual []byte
		require.NoError(t, store.ReadShelf(ctx, "metadata", func(reader stoabs.Reader) error {
			var err error
			actual, err = reader.Get(key)
			return err
		}))
		assert.Equal(t, []byte{1, 2, 3}, actual)
		// same name returns the same store
		again, err := e.GetProvider("Network").GetKVStore("data", PersistentStorageClass)
		require.NoError(t, err)
		assert.Same(t, store, again)
	})
	t.Run("volatile class is served by the SQL database as well", func(t *testing.T) {
		e := NewTestStorageEngineSQLKV(t)
		store, err := e.GetProvider("Network").GetKVStore("connections", VolatileStorageClass)
		require.NoError(t, err)
		require.NoError(t, store.WriteShelf(ctx, "backoff", func(writer stoabs.Writer) error {
			return writer.Put(stoabs.BytesKey("peer"), []byte{1})
		}))
	})
	t.Run("nested read transactions on different stores do not deadlock (SQLite)", func(t *testing.T) {
		// The DAG verifies a transaction by resolving its signing key from the DID store while its own read
		// transaction is open. With SQLite's single-connection pool that would deadlock, hence the dedicated handle.
		e := NewTestStorageEngineSQLKV(t)
		dag, err := e.GetProvider("Network").GetKVStore("data", PersistentStorageClass)
		require.NoError(t, err)
		didStore, err := e.GetProvider("VDR").GetKVStore("didstore", PersistentStorageClass)
		require.NoError(t, err)
		require.NoError(t, didStore.WriteShelf(ctx, "latestV2", func(writer stoabs.Writer) error {
			return writer.Put(stoabs.BytesKey("did:nuts:1"), []byte("ref"))
		}))
		done := make(chan error, 1)
		go func() {
			done <- dag.Read(ctx, func(outer stoabs.ReadTx) error {
				return didStore.ReadShelf(ctx, "latestV2", func(reader stoabs.Reader) error {
					_, err := reader.Get(stoabs.BytesKey("did:nuts:1"))
					return err
				})
			})
		}()
		select {
		case err := <-done:
			assert.NoError(t, err)
		case <-time.After(10 * time.Second):
			t.Fatal("nested read transactions deadlocked")
		}
	})
	t.Run("write on one store while a read is open on another (SQLite)", func(t *testing.T) {
		e := NewTestStorageEngineSQLKV(t)
		dag, err := e.GetProvider("Network").GetKVStore("data", PersistentStorageClass)
		require.NoError(t, err)
		didStore, err := e.GetProvider("VDR").GetKVStore("didstore", PersistentStorageClass)
		require.NoError(t, err)
		done := make(chan error, 1)
		go func() {
			done <- dag.Read(ctx, func(outer stoabs.ReadTx) error {
				return didStore.WriteShelf(ctx, "latestV2", func(writer stoabs.Writer) error {
					return writer.Put(stoabs.BytesKey("did:nuts:2"), []byte("ref"))
				})
			})
		}()
		select {
		case err := <-done:
			assert.NoError(t, err)
		case <-time.After(10 * time.Second):
			t.Fatal("write inside read transaction deadlocked")
		}
	})
	t.Run("unknown shelf fails loud", func(t *testing.T) {
		e := NewTestStorageEngineSQLKV(t)
		store, err := e.GetProvider("Network").GetKVStore("data", PersistentStorageClass)
		require.NoError(t, err)
		err = store.WriteShelf(ctx, "not-in-inventory", func(writer stoabs.Writer) error {
			return writer.Put(stoabs.BytesKey("k"), []byte("v"))
		})
		assert.ErrorIs(t, err, stoabs.ErrDatabase{})
	})
	t.Run("invalid backend", func(t *testing.T) {
		e := New().(*engine)
		e.config = DefaultConfig()
		e.config.KV.Backend = "etcd"
		err := e.Configure(core.ServerConfig{Datadir: io.TestDirectory(t)})
		assert.EqualError(t, err, `invalid storage.kv.backend: "etcd" (valid values: bbolt, sql)`)
	})
	t.Run("sql backend can't be combined with Redis KV storage", func(t *testing.T) {
		e := New().(*engine)
		e.config = DefaultConfig()
		e.config.KV.Backend = KVBackendSQL
		e.config.Redis.Address = "localhost:6379"
		err := e.Configure(core.ServerConfig{Datadir: io.TestDirectory(t)})
		assert.EqualError(t, err, "storage.redis can't be combined with storage.kv.backend=sql")
	})
	t.Run("bbolt backend is the default and still creates the tables", func(t *testing.T) {
		e := NewTestStorageEngine(t).(*engine)
		_, ok := e.databases[0].(*bboltDatabase)
		assert.True(t, ok)
		assert.True(t, e.sqlDB.Migrator().HasTable(sql_migrations.KVShelves[0].TableName()))
	})
	t.Run("shutdown closes the dedicated SQLite handle", func(t *testing.T) {
		e := NewTestStorageEngineSQLKV(t).(*engine)
		kv := e.databases[0].(*sqlKVDatabase)
		require.True(t, kv.ownsDB)
		require.NoError(t, e.Shutdown())
		assert.Error(t, kv.db.Ping())
	})
}

func TestNewSQLKVDatabase(t *testing.T) {
	_, err := newSQLKVDatabase("oracle", nil, "")
	assert.EqualError(t, err, "unsupported SQL database type for KV stores: oracle")
	for _, dbType := range []string{"postgres", "mysql", "sqlserver", "azuresql"} {
		db, err := newSQLKVDatabase(dbType, nil, "")
		require.NoError(t, err)
		assert.False(t, db.ownsDB)
		assert.Equal(t, Class(PersistentStorageClass), db.getClass())
	}
}
