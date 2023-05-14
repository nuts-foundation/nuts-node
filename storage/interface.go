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
	"database/sql"
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/nuts-node/core"
	"time"
)

const lockAcquireTimeout = time.Second

// Engine defines the interface for the storage engine.
type Engine interface {
	core.Engine
	core.Configurable
	core.Runnable

	// GetProvider returns the Provider for the given module.
	GetProvider(moduleName string) Provider
}

// Provider lets callers get access to stores.
type Provider interface {
	// GetKVStore returns a key-value store. Stores are identified by a name.
	// When identical name is passed the same store is returned.
	// Names must be alphanumeric, non-zero strings.
	GetKVStore(name string, class Class) (stoabs.KVStore, error)

	// GetSQLStore returns a SQL store, if configured. It returns nil if no SQL store is configured.
	GetSQLStore() *sql.DB
}

// Class defines levels of storage reliability.
type Class int

const (
	// VolatileStorageClass means losing the storage has no/little implications due to data loss (e.g. caches).
	VolatileStorageClass Class = iota
	// PersistentStorageClass means losing the storage should never happen, because it has major implications.
	PersistentStorageClass = iota
)

type database interface {
	createStore(moduleName string, storeName string) (stoabs.KVStore, error)
	getClass() Class
	close()
}
