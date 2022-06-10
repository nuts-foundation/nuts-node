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
	"encoding/json"
	"fmt"
)

// DatabaseType defines a type for naming supported databases.
type DatabaseType string

// DefaultConfig returns the default configuration for the storage engine.
func DefaultConfig() Config {
	return Config{
		Databases: map[string]DatabaseConfig{},
	}
}

// Config specifies config for the storage engine.
type Config struct {
	// Databases specifies config for supported databases.
	Databases map[string]DatabaseConfig `koanf:"databases"`
}

func (c Config) getDatabaseByType(dbType DatabaseType) *DatabaseConfig {
	for _, db := range c.Databases {
		if db.Type == dbType {
			return &db
		}
	}
	return nil
}

func (c Config) validate() error {
	// Assert there's only 1 type of each database configured
	mapOfTypes := make(map[DatabaseType]bool, 0)
	for _, db := range c.Databases {
		if mapOfTypes[db.Type] {
			return fmt.Errorf("multiple databases of type '%s' configured", db.Type)
		}
		mapOfTypes[db.Type] = true
	}
	return nil
}

// DatabaseConfig specifies config for a database.
type DatabaseConfig struct {
	// Type holds the type of the database.
	Type DatabaseType `koanf:"type"`
	// Config holds the type-specific config for the database.
	Config interface{} `koanf:"config"`
}

// UnmarshalConfig reads to config into a database specific configuration type.
func (d DatabaseConfig) UnmarshalConfig(target interface{}) error {
	configAsBytes, _ := json.Marshal(d.Config)
	return json.Unmarshal(configAsBytes, target)
}

// BBoltConfig specifies config for BBolt databases.
type BBoltConfig struct {
	// Backup specifies backup config for the database.
	Backup BBoltBackupConfig `koanf:"backup"`
}

// BBoltBackupConfig specifies config for BBolt database backups.
type BBoltBackupConfig struct {
	// Directory specifies the directory in which the BBolt backup should be written.
	Directory string `koanf:"directory"`
	// Interval specifies the time between backups.
	Interval MarshallingDuration `koanf:"interval"`
}
