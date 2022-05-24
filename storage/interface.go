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
	"github.com/nuts-foundation/go-storage/api"
	"github.com/nuts-foundation/nuts-node/core"
)

// Engine defines the interface for the storage engine.
type Engine interface {
	core.Engine
	core.Configurable
	core.Runnable
	Provider
}

// Provider lets callers get access to stores.
type Provider interface {
	// GetIterableKVStore returns a key-value store like KVStore, but then iterable (supporting cursors).
	GetIterableKVStore(namespace string, name string) (api.IterableKVStore, error)

	// GetKVStore returns a key-value store. Stores are created in a namespace identified by a name.
	// When identical namespace/name is passed the same store is returned.
	// Store names may appear in multiple namespaces.
	// Namespaces and names must be alphanumeric, non-zero strings.
	GetKVStore(namespace string, name string) (api.KVStore, error)
}
