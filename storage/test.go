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
	"database/sql"
	"errors"
	"fmt"
	"github.com/alicebob/miniredis/v2"
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/nuts-node/v6/test/io"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-stoabs/bbolt"
	"github.com/nuts-foundation/nuts-node/v6/core"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func NewTestStorageRedisEngineInDir(t testing.TB, dir string) (Engine, *miniredis.Miniredis) {
	result := New().(*engine)
	// Prevent dbmate and gorm from logging database creation and applied schema migrations.
	// These are logged on INFO, which is good for production but annoying in unit tests.
	result.sqlMigrationLogger = nilGooseLogger{}

	result.config.SQL = SQLConfig{ConnectionString: sqliteConnectionString(dir)}
	redis := miniredis.RunT(t)
	result.config.Session.Redis = RedisConfig{Address: redis.Addr()}
	err := result.Configure(core.TestServerConfig(func(config *core.ServerConfig) {
		config.Datadir = dir + "/data"
	}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = result.Shutdown()
	})
	return result, redis
}

func NewTestStorageEngineInDir(t testing.TB, dir string) Engine {
	result := New().(*engine)
	result.config = DefaultConfig()
	// Prevent goose and gorm from logging database creation and applied schema migrations.
	// These are logged on INFO, which is good for production but annoying in unit tests.
	result.sqlMigrationLogger = nilGooseLogger{}

	result.config.SQL = SQLConfig{ConnectionString: sqliteConnectionString(dir)}
	err := result.Configure(core.TestServerConfig(func(config *core.ServerConfig) {
		config.Datadir = dir + "/data"
	}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = result.Shutdown()
	})
	fmt.Printf("Created test storage engine in %s\n", dir)
	return result
}

func NewTestStorageEngine(t testing.TB) Engine {
	oldOpts := DefaultBBoltOptions[:]
	t.Cleanup(func() {
		DefaultBBoltOptions = oldOpts
	})
	DefaultBBoltOptions = append(DefaultBBoltOptions, stoabs.WithNoSync())
	return NewTestStorageEngineInDir(t, io.TestDirectory(t))
}

func NewTestStorageEngineRedis(t testing.TB) (Engine, *miniredis.Miniredis) {
	oldOpts := DefaultBBoltOptions[:]
	t.Cleanup(func() {
		DefaultBBoltOptions = oldOpts
	})
	DefaultBBoltOptions = append(DefaultBBoltOptions, stoabs.WithNoSync())
	return NewTestStorageRedisEngineInDir(t, io.TestDirectory(t))
}

// CreateTestBBoltStore creates an in-memory bbolt store
func CreateTestBBoltStore(tb testing.TB, filePath string) stoabs.KVStore {
	db, err := bbolt.CreateBBoltStore(filePath, stoabs.WithNoSync())
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() {
		db.Close(context.Background())
	})
	return db
}

// StaticKVStoreProvider contains a single store.
type StaticKVStoreProvider struct {
	Store stoabs.KVStore
}

// GetKVStore ignores the inputs and returns the Store, or an error when Store == nil.
func (p *StaticKVStoreProvider) GetKVStore(_ string, _ Class) (stoabs.KVStore, error) {
	if p.Store == nil {
		return nil, errors.New("no store available")
	}
	return p.Store, nil
}

func NewTestInMemorySessionDatabase(t *testing.T) *InMemorySessionDatabase {
	db := NewInMemorySessionDatabase()
	t.Cleanup(func() {
		db.Close()
	})
	return db
}

func AddDIDtoSQLDB(t testing.TB, db *gorm.DB, dids ...did.DID) {
	for _, id := range dids {
		// use gorm EXEC since it accepts '?' as the argument placeholder for all DBs
		require.NoError(t, db.Exec("INSERT INTO did ( subject, id ) VALUES ( ?, ? )", id.String(), id.String(), id.String()).Error)
	}
}

// TestKVSQLConnectionEnv names the environment variable with a PostgreSQL connection string (nuts format,
// e.g. postgres://nuts:nuts@localhost:5432/nuts?sslmode=disable) used by tests of the SQL KV backend.
// The backend needs a database server (SQLite is not supported), so these tests are skipped when it is unset.
const TestKVSQLConnectionEnv = "NUTS_TEST_KV_SQL_CONNECTION"

// NewTestStorageEngineSQLKV creates a storage engine with the key-value stores on SQL (storage.kv.backend=sql),
// on a schema of its own in the PostgreSQL database named by TestKVSQLConnectionEnv. Skips the test when unset.
func NewTestStorageEngineSQLKV(t testing.TB) Engine {
	return NewTestStorageEngineSQLKVInDir(t, io.TestDirectory(t))
}

// NewTestStorageEngineSQLKVInDir is NewTestStorageEngineSQLKV on the given directory, which lets a test start a
// bbolt-backed engine first and then switch the same data directory to the SQL KV backend.
func NewTestStorageEngineSQLKVInDir(t testing.TB, dir string) Engine {
	result := newTestStorageEngineSQLKVUnconfigured(t)
	err := result.Configure(core.TestServerConfig(func(config *core.ServerConfig) {
		config.Datadir = dir + "/data"
	}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = result.Shutdown()
	})
	return result
}

// newTestStorageEngineSQLKVUnconfigured returns an engine configured for the SQL KV backend on a fresh PostgreSQL
// schema, without calling Configure, so tests can exercise Configure's failure paths.
// Isolation per test: a schema is created and put first in search_path, and dropped on cleanup. The node's own tables
// (including goose's version table) therefore land in the test's schema.
func newTestStorageEngineSQLKVUnconfigured(t testing.TB) *engine {
	dsn := os.Getenv(TestKVSQLConnectionEnv)
	if dsn == "" {
		t.Skipf("%s not set, skipping SQL KV backend test", TestKVSQLConnectionEnv)
	}
	if !strings.HasPrefix(dsn, "postgres://") {
		t.Fatalf("%s must be a postgres:// connection string", TestKVSQLConnectionEnv)
	}
	schema := fmt.Sprintf("kvtest_%d_%d", os.Getpid(), testSchemaCounter.Add(1))
	admin, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	_, err = admin.Exec("CREATE SCHEMA " + schema)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = admin.Exec("DROP SCHEMA " + schema + " CASCADE")
		_ = admin.Close()
	})
	separator := "?"
	if strings.Contains(dsn, "?") {
		separator = "&"
	}
	result := New().(*engine)
	result.config = DefaultConfig()
	result.sqlMigrationLogger = nilGooseLogger{}
	result.config.SQL = SQLConfig{ConnectionString: dsn + separator + "search_path=" + schema}
	result.config.KV.Backend = KVBackendSQL
	return result
}

var testSchemaCounter atomic.Int64

type nilGooseLogger struct{}

func (m nilGooseLogger) Printf(format string, v ...interface{}) {}

func (m nilGooseLogger) Fatalf(format string, v ...interface{}) {}

var _ SessionDatabase = (*errorSessionDatabase)(nil)
var _ SessionStore = (*errorSessionStore)(nil)

// NewErrorSessionDatabase creates a SessionDatabase that always returns an error.
func NewErrorSessionDatabase(err error) SessionDatabase {
	return errorSessionDatabase{err: err}
}

type errorSessionDatabase struct {
	err error
}

type errorSessionStore struct {
	err error
}

func (e errorSessionDatabase) GetStore(ttl time.Duration, keys ...string) SessionStore {
	return errorSessionStore{err: e.err}
}

func (e errorSessionDatabase) getFullKey(prefixes []string, key string) string {
	return ""
}

func (e errorSessionDatabase) Close() {
	// nop
}

func (e errorSessionStore) Delete(key string) error {
	return e.err
}

func (e errorSessionStore) Exists(key string) bool {
	return false
}

func (e errorSessionStore) Get(key string, target interface{}) error {
	return e.err
}

func (e errorSessionStore) Put(key string, value interface{}, options ...SessionOption) error {
	return e.err
}

func (e errorSessionStore) GetAndDelete(key string, target interface{}) error {
	return e.err
}
