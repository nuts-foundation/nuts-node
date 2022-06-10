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
	"fmt"
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/storage/log"
	"strings"
	"sync"
	"time"
)

const storeShutdownTimeout = 5 * time.Second

// New creates a new instance of the storage engine.
func New() Engine {
	return &engine{
		storesMux: &sync.Mutex{},
		stores:    map[string]stoabs.Store{},
	}
}

type engine struct {
	datadir   string
	storesMux *sync.Mutex
	stores    map[string]stoabs.Store
	databases []databaseAdapter
	config    Config
}

func (e engine) Config() interface{} {
	return &e.config
}

// Name returns the name of the engine.
func (e engine) Name() string {
	return "Storage"
}

func (e engine) Start() error {
	return nil
}

func (e engine) Shutdown() error {
	e.storesMux.Lock()
	defer e.storesMux.Unlock()

	shutdown := func(store stoabs.Store) error {
		// Refactored to separate function, otherwise defer would be in for loop which leaks resources.
		ctx, cancel := context.WithTimeout(context.Background(), storeShutdownTimeout)
		defer cancel()
		return store.Close(ctx)
	}

	failures := false
	for storeName, store := range e.stores {
		err := shutdown(store)
		if err != nil {
			log.Logger().Errorf("Failed to close store '%s': %s", storeName, err)
			failures = true
		}
	}
	if failures {
		return errors.New("one or more stores failed to close")
	}
	return nil
}

func (e *engine) Configure(config core.ServerConfig) error {
	e.datadir = config.Datadir

	// Register databases
	for _, database := range e.config.Databases {
		if e.isDatabaseRegistered(database.Type) {
			// TODO: Will be supported in future
			return fmt.Errorf("multiple databases configured of type '%s' (which is not supported)", database.Type)
		}
		switch database.Type {
		// TODO: add more
		case BBoltDatabaseType:
			e.databases = append(e.databases, &bboltDatabaseAdapter{
				datadir: e.datadir,
				config:  database,
			})
		default:
			return fmt.Errorf("unsupported database type: %s", database.Type)
		}
	}
	// Now register default database(s):
	if !e.isDatabaseRegistered(BBoltDatabaseType) {
		e.databases = append(e.databases, &bboltDatabaseAdapter{datadir: e.datadir})
	}
	return nil
}

func (e *engine) GetProvider(moduleName string) Provider {
	return &provider{
		moduleName: strings.ToLower(moduleName),
		engine:     e,
	}
}

func (e *engine) isDatabaseRegistered(dbType DatabaseType) bool {
	for _, db := range e.databases {
		if db.getType() == dbType {
			return true
		}
	}
	return false
}

type provider struct {
	moduleName string
	engine     *engine
}

func (p *provider) GetKVStore(name string, class Class) (stoabs.KVStore, error) {
	p.engine.storesMux.Lock()
	defer p.engine.storesMux.Unlock()

	// TODO: For now, we ignore class since we only support BBolt.
	// When other database types with other storage classes are supported (e.g. Redis) we'll be matching them here,
	// to find the right one:
	// 1. Check manual binding of specific store to a configured database (e.g. `network/connections -> redis0`)
	// 2. Otherwise: find database whose storage class matches the requested class
	// 3. Otherwise (if no storage class matches, e.g. no `persistent` database configured): use "lower" storage class, but only in non-strict mode.
	store, err := p.getStore(p.moduleName, name, p.engine.databases[0])
	if store == nil {
		return nil, err
	}
	return store.(stoabs.KVStore), err
}

func (p *provider) getStore(moduleName string, name string, adapter databaseAdapter) (stoabs.Store, error) {
	if len(moduleName) == 0 {
		return nil, errors.New("invalid store moduleName")
	}
	if len(name) == 0 {
		return nil, errors.New("invalid store name")
	}
	key := moduleName + "/" + name
	store := p.engine.stores[key]
	if store != nil {
		return store, nil
	}
	store, err := adapter.createStore(moduleName, name)
	if err == nil {
		p.engine.stores[key] = store
	}
	return store, err
}
