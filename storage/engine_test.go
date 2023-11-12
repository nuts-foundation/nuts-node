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
	"errors"
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"os"
	"path"
	"testing"
)

func Test_New(t *testing.T) {
	assert.NotNil(t, New())
}

func Test_engine_Name(t *testing.T) {
	assert.Equal(t, "Storage", (&engine{}).Name())
}

func Test_engine_lifecycle(t *testing.T) {
	sut := NewTestStorageEngine(t)
	err := sut.Start()
	require.NoError(t, err)
	// Get a KV store so there's something to shut down
	_, err = sut.GetProvider("test").GetKVStore("store", VolatileStorageClass)
	require.NoError(t, err)
	err = sut.Shutdown()
	require.NoError(t, err)
}

func Test_engine_GetProvider(t *testing.T) {
	sut := New()
	_ = sut.Configure(*core.NewServerConfig())
	t.Run("moduleName is empty", func(t *testing.T) {
		store, err := sut.GetProvider("").GetKVStore("store", VolatileStorageClass)
		assert.Nil(t, store)
		assert.EqualError(t, err, "invalid store moduleName")
	})
}

func Test_engine_GetKVStore(t *testing.T) {
	sut := New()
	_ = sut.Configure(*core.NewServerConfig())
	t.Run("store is empty", func(t *testing.T) {
		store, err := sut.GetProvider("engine").GetKVStore("", VolatileStorageClass)
		assert.Nil(t, store)
		assert.EqualError(t, err, "invalid store name")
	})
}

func Test_engine_Shutdown(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		store := stoabs.NewMockKVStore(ctrl)
		store.EXPECT().Close(gomock.Any())

		sut := New().(*engine)
		sut.stores["1"] = store

		err := sut.Shutdown()

		assert.NoError(t, err)
	})
	t.Run("error while closing store results in error, but all stores are closed", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		store1 := stoabs.NewMockKVStore(ctrl)
		store1.EXPECT().Close(gomock.Any()).Return(errors.New("failed"))
		store2 := stoabs.NewMockKVStore(ctrl)
		store2.EXPECT().Close(gomock.Any()).Return(errors.New("failed"))

		sut := New().(*engine)
		sut.stores["1"] = store1
		sut.stores["2"] = store2

		err := sut.Shutdown()

		assert.EqualError(t, err, "one or more stores failed to close")
	})
}

func Test_engine_sqlDatabase(t *testing.T) {
	t.Run("defaults to SQLite in data directory", func(t *testing.T) {
		e := New()
		dataDir := io.TestDirectory(t)
		require.NoError(t, e.Configure(core.ServerConfig{Datadir: dataDir}))
		require.NoError(t, e.Start())
		t.Cleanup(func() {
			_ = e.Shutdown()
		})
		assert.FileExists(t, path.Join(dataDir, "sqlite.db"))
	})
	t.Run("unable to open SQLite database", func(t *testing.T) {
		dataDir := io.TestDirectory(t)
		require.NoError(t, os.Remove(dataDir))
		e := New()
		require.NoError(t, e.Configure(core.ServerConfig{Datadir: dataDir}))
		err := e.Start()
		assert.EqualError(t, err, "failed to initialize SQL database: unable to open database file")
	})
	t.Run("nothing to migrate (already migrated)", func(t *testing.T) {
		dataDir := io.TestDirectory(t)
		e := New()
		require.NoError(t, e.Configure(core.ServerConfig{Datadir: dataDir}))
		require.NoError(t, e.Start())
		require.NoError(t, e.Shutdown())
		e = New()
		require.NoError(t, e.Configure(core.ServerConfig{Datadir: dataDir}))
		require.NoError(t, e.Start())
		require.NoError(t, e.Shutdown())
	})
	t.Run("runs migrations", func(t *testing.T) {
		e := New().(*engine)
		e.config.SQL.ConnectionString = SQLiteInMemoryConnectionString
		require.NoError(t, e.Configure(*core.NewServerConfig()))
		require.NoError(t, e.Start())
		t.Cleanup(func() {
			_ = e.Shutdown()
		})

		underlyingDB, err := e.GetSQLDatabase().DB()
		require.NoError(t, err)
		row := underlyingDB.QueryRow("SELECT count(*) FROM schema_migrations")
		require.NoError(t, row.Err())
		var count int
		assert.NoError(t, row.Scan(&count))
		assert.Equal(t, 1, count)
	})

}
