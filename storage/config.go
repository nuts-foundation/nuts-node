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

// Config specifies config for the storage engine.
type Config struct {
	BBolt   BBoltConfig   `koanf:"bbolt"`
	Redis   RedisConfig   `koanf:"redis"`
	SQL     SQLConfig     `koanf:"sql"`
	Session SessionConfig `koanf:"session"`
}

// DefaultConfig returns the default configuration for the module.
func DefaultConfig() Config {
	return Config{
		Session: SessionConfig{Redis: RedisConfig{}},
	}
}

// SQLConfig specifies config for the SQL storage engine.
type SQLConfig struct {
	// ConnectionString is the connection string for the SQL database.
	// This string may contain secrets (user:password), so should never be logged.
	ConnectionString string `koanf:"connection"`
}

// SessionConfig specifies config for the session storage engine.
type SessionConfig struct {
	// Type is the type of session storage engine to use.
	Redis RedisConfig `koanf:"redis"`
}
