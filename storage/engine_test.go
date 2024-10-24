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
	"github.com/alicebob/miniredis/v2"
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"os"
	"path"
	"strings"
	"testing"
	"time"
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
	_ = sut.Configure(core.ServerConfig{Datadir: io.TestDirectory(t)})
	t.Run("moduleName is empty", func(t *testing.T) {
		store, err := sut.GetProvider("").GetKVStore("store", VolatileStorageClass)
		assert.Nil(t, store)
		assert.EqualError(t, err, "invalid store moduleName")
	})
}

func Test_engine_GetKVStore(t *testing.T) {
	sut := New()
	_ = sut.Configure(core.ServerConfig{Datadir: io.TestDirectory(t)})
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
		assert.NoError(t, sut.Configure(core.ServerConfig{Datadir: io.TestDirectory(t)}))

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
		e.(*engine).datadir = dataDir
		err := e.(*engine).initSQLDatabase(false)
		assert.ErrorContains(t, err, "unable to open database file")
	})
	t.Run("no DB configured in strictmode", func(t *testing.T) {
		e := New()
		e.(*engine).datadir = io.TestDirectory(t)
		err := e.(*engine).initSQLDatabase(true)
		assert.ErrorContains(t, err, "no database configured: storage.sql.connection must be set in strictmode")
	})
	t.Run("sqlite is restricted to 1 connection", func(t *testing.T) {
		e := New()
		require.NoError(t, e.Configure(core.ServerConfig{Datadir: t.TempDir()}))
		require.NoError(t, e.Start())
		t.Cleanup(func() {
			_ = e.Shutdown()
		})
		e2, ok := e.(*engine)
		require.True(t, ok)
		db, err := e2.sqlDB.DB()
		require.NoError(t, err)
		assert.Equal(t, 1, db.Stats().MaxOpenConnections)
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
		require.NoError(t, e.Configure(core.ServerConfig{Datadir: io.TestDirectory(t)}))
		require.NoError(t, e.Start())
		t.Cleanup(func() {
			_ = e.Shutdown()
		})

		// count .sql files in sql_migration directory
		files, err := os.ReadDir("sql_migrations")
		var sqlFiles []string
		for _, curr := range files {
			if strings.HasSuffix(curr.Name(), ".sql") {
				sqlFiles = append(sqlFiles, curr.Name())
			}
		}
		require.NoError(t, err)

		underlyingDB, err := e.GetSQLDatabase().DB()
		require.NoError(t, err)
		rows, err := underlyingDB.Query("SELECT * FROM goose_db_version")
		require.NoError(t, err)
		var pKey, versionId, is_applied int
		var tStamp time.Time
		var totalMigrations int
		rows.Next()
		for err = rows.Scan(&pKey, &versionId, &is_applied, &tStamp); rows.Next() && err == nil; {
			assert.Equal(t, 1, is_applied)
			totalMigrations++
		}
		require.NoError(t, err)
		assert.Equal(t, len(sqlFiles), totalMigrations) // up and down migration files
	})
	t.Run("unsupported protocol doesn't log secrets", func(t *testing.T) {
		dataDir := io.TestDirectory(t)
		require.NoError(t, os.Remove(dataDir))
		e := New()
		e.(*engine).config.SQL.ConnectionString = "fake://user:password@example.com:123/db"
		err := e.Configure(core.ServerConfig{Datadir: dataDir})
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "user:password")
	})
	t.Run("session storage", func(t *testing.T) {
		t.Run("in-memory is default", func(t *testing.T) {
			e := New()
			dataDir := io.TestDirectory(t)
			require.NoError(t, e.Configure(core.ServerConfig{Datadir: dataDir}))
			require.NoError(t, e.Start())
			t.Cleanup(func() {
				_ = e.Shutdown()
			})
			assert.IsType(t, &InMemorySessionDatabase{}, e.GetSessionDatabase())
		})
		t.Run("in-memory", func(t *testing.T) {
			e := New().(*engine)
			e.config = Config{
				Session: SessionConfig{},
			}
			dataDir := io.TestDirectory(t)
			require.NoError(t, e.Configure(core.ServerConfig{Datadir: dataDir}))
			require.NoError(t, e.Start())
			t.Cleanup(func() {
				_ = e.Shutdown()
			})
			assert.IsType(t, &InMemorySessionDatabase{}, e.GetSessionDatabase())
		})
	})
}

func TestEngine_CheckHealth(t *testing.T) {
	setup := func(t *testing.T) *engine {
		e := New().(*engine)
		dataDir := io.TestDirectory(t)
		require.NoError(t, e.Configure(core.ServerConfig{Datadir: dataDir}))
		require.NoError(t, e.Start())
		t.Cleanup(func() {
			_ = e.Shutdown()
		})
		return e
	}
	t.Run("no SQL doesn't panic", func(t *testing.T) {
		assert.Empty(t, new(engine).CheckHealth())
	})
	t.Run("ok", func(t *testing.T) {
		expected := core.Health{Status: core.HealthStatusUp}
		e := setup(t)
		health := e.CheckHealth()
		status, ok := health["sql"]
		require.True(t, ok)
		assert.Equal(t, expected, status)
	})
	t.Run("fails", func(t *testing.T) {
		expected := core.Health{
			Status:  core.HealthStatusDown,
			Details: "sql: database is closed",
		}
		e := setup(t)
		db, err := e.sqlDB.DB()
		require.NoError(t, err)
		require.NoError(t, db.Close())

		health := e.CheckHealth()
		status, ok := health["sql"]
		require.True(t, ok)
		assert.Equal(t, expected, status)
	})
}

func Test_engine_redisSessionDatabase(t *testing.T) {
	t.Run("redis", func(t *testing.T) {
		redis := miniredis.RunT(t)
		e := New().(*engine)
		e.config = Config{
			Session: SessionConfig{
				Redis: RedisConfig{Address: redis.Addr()},
			},
		}
		dataDir := io.TestDirectory(t)
		require.NoError(t, e.Configure(core.ServerConfig{Datadir: dataDir}))
		require.NoError(t, e.Start())
		t.Cleanup(func() {
			_ = e.Shutdown()
		})
		assert.IsType(t, redisSessionDatabase{}, e.GetSessionDatabase())
	})
}
