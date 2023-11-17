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
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/go-stoabs/bbolt"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/test/io"
	"testing"
)

// SQLiteInMemoryConnectionString is a connection string for an in-memory SQLite database
const SQLiteInMemoryConnectionString = "file::memory:?cache=shared"

func NewTestStorageEngineInDir(dir string) Engine {
	result := New().(*engine)
	result.config.SQL = SQLConfig{ConnectionString: SQLiteInMemoryConnectionString}
	//result.config.SQL = SQLConfig{ConnectionString: "file:../../data/sqlite.db"}
	_ = result.Configure(core.TestServerConfig(core.ServerConfig{Datadir: dir + "/data"}))
	return result
}

func NewTestStorageEngine(t testing.TB) Engine {
	oldOpts := append(DefaultBBoltOptions[:])
	t.Cleanup(func() {
		DefaultBBoltOptions = oldOpts
	})
	DefaultBBoltOptions = append(DefaultBBoltOptions, stoabs.WithNoSync())
	return NewTestStorageEngineInDir(io.TestDirectory(t))
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
		db.close()
	})
	return db
}
