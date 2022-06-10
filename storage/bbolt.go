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
	"fmt"
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/go-stoabs/bbolt"
	"path"
)

// BBoltDatabaseType holds the type name of BBolt databases.
const BBoltDatabaseType DatabaseType = "bbolt"

type bboltDatabaseAdapter struct {
	datadir string
	config  DatabaseConfig
}

func (b bboltDatabaseAdapter) createStore(moduleName string, storeName string) (stoabs.KVStore, error) {
	var bboltConfig BBoltConfig
	err := b.config.UnmarshalConfig(&bboltConfig)
	if err != nil {
		return nil, fmt.Errorf("invalid BBolt database config: %w", err)
	}
	// TODO: Do something with the config (e.g. start backup background procedure)
	databasePath := path.Join(b.datadir, moduleName, storeName+".db")
	return bbolt.CreateBBoltStore(databasePath)
}

func (b bboltDatabaseAdapter) getClass() Class {
	return VolatileStorageClass
}

func (b bboltDatabaseAdapter) getType() DatabaseType {
	return BBoltDatabaseType
}
