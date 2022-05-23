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
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/storage/log"
	"path"
)

// New creates a new instance of the storage engine.
func New() Engine {
	return &engine{stores: map[string]KVStore{}}
}

type engine struct {
	datadir string
	stores  map[string]KVStore
}

// Name returns the name of the engine.
func (e engine) Name() string {
	return "Storage"
}

func (e engine) Start() error {
	return nil
}

func (e engine) Shutdown() error {
	failures := false
	for storeName, store := range e.stores {
		err := store.Close()
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

func (e *engine) GetKVStore(namespace string, name string) (KVStore, error) {
	if len(namespace) == 0 {
		return nil, errors.New("invalid store namespace")
	}
	if len(name) == 0 {
		return nil, errors.New("invalid store name")
	}
	store, err := CreateBBoltStore(path.Join(e.datadir, namespace, name+".db"))
	if err == nil {
		e.stores[namespace+"/"+name] = store
	}
	return store, err
}
