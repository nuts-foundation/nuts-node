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
	"github.com/nuts-foundation/go-stoabs"
	bbolt "github.com/nuts-foundation/go-stoabs/badger"
	"github.com/nuts-foundation/nuts-node/storage/log"
	"path"
	"sync"
)

type badgerDatabase struct {
	datadir         string
	config          BBoltConfig
	ctx             context.Context
	cancel          context.CancelFunc
	shutdownWatcher *sync.WaitGroup
}

func createBadgerDatabase(datadir string) (*badgerDatabase, error) {
	result := badgerDatabase{
		datadir:         datadir,
		shutdownWatcher: &sync.WaitGroup{},
	}
	// Create context for initiating shutdown
	result.ctx, result.cancel = context.WithCancel(context.Background())
	return &result, nil
}

func (b badgerDatabase) createStore(moduleName string, storeName string) (stoabs.KVStore, error) {
	log.Logger().Debugf("Creating Badger store (module=%s,store=%s)", moduleName, storeName)
	databasePath := path.Join(b.datadir, b.getRelativeStorePath(moduleName, storeName))
	store, err := bbolt.CreateBadgerStore(databasePath)

	return store, err
}

func (b badgerDatabase) getClass() Class {
	return VolatileStorageClass
}

func (b badgerDatabase) close() {
	// Signal backup processes to stop
	b.cancel()
	// Wait for backup processes to finish
	b.shutdownWatcher.Wait()
}

func (b badgerDatabase) getRelativeStorePath(moduleName string, storeName string) string {
	return path.Join(moduleName, storeName+".db")
}
