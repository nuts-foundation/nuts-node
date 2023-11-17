/*
 * Copyright (C) 2023 Nuts community
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

package discoveryservice

// Config holds the config of the module
type Config struct {
	Server      ServerConfig      `koanf:"server"`
	Definitions DefinitionsConfig `koanf:"definitions"`
}

// DefinitionsConfig holds the config for loading Service Definitions.
type DefinitionsConfig struct {
	Directory string `koanf:"directory"`
}

// ServerConfig holds the config for the server
type ServerConfig struct {
	// DefinitionIDs specifies which use case lists the server serves.
	DefinitionIDs []string `koanf:"definition_ids"`
	// Directory is the directory where the server stores the lists.
	Directory string `koanf:"directory"`
}

// DefaultConfig returns the default configuration.
func DefaultConfig() Config {
	return Config{
		Server: ServerConfig{},
	}
}

// IsServer returns true if the node act as Discovery Server.
func (c Config) IsServer() bool {
	return len(c.Server.DefinitionIDs) > 0
}
