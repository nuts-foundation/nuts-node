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
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/go-stoabs/bbolt"
	"github.com/nuts-foundation/nuts-node/core"
	"testing"
)

func NewTestStorageEngine(testDirectory string) Engine {
	result := New()
	_ = result.Configure(core.TestServerConfig(core.ServerConfig{Datadir: testDirectory + "/data"}))
	return result
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

func (p *StaticKVStoreProvider) GetSQLStore() *sql.DB {
	panic("implement me")
}

// GetKVStore ignores the inputs and returns the Store, or an error when Store == nil.
func (p *StaticKVStoreProvider) GetKVStore(_ string, _ Class) (stoabs.KVStore, error) {
	if p.Store == nil {
		return nil, errors.New("no store available")
	}
	return p.Store, nil
}
