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
	"github.com/nuts-foundation/nuts-node/storage/log"
	"path"
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
	return nil
}

func (e *engine) GetProvider(moduleName string) Provider {
	return &provider{
		moduleName: strings.ToLower(moduleName),
		engine:     e,
	}
}

type provider struct {
	moduleName string
	engine     *engine
}

func (p *provider) GetKVStore(name string) (stoabs.KVStore, error) {
	p.engine.storesMux.Lock()
	defer p.engine.storesMux.Unlock()

	store, err := p.getStore(p.moduleName, name, func(moduleName string, name string) (stoabs.Store, error) {
		return bbolt.CreateBBoltStore(path.Join(p.engine.datadir, moduleName, name+".db"))
	})
	if store == nil {
		return nil, err
	}
	return store.(stoabs.KVStore), err
}

func (p *provider) getStore(moduleName string, name string, creator func(namespace string, name string) (stoabs.Store, error)) (stoabs.Store, error) {
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
	store, err := creator(moduleName, name)
	if err == nil {
		p.engine.stores[key] = store
	}
	return store, err
}
