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

package usecase

import "time"

// Config holds the config for use case listDefinition
type Config struct {
	Maintainer  MaintainerConfig  `koanf:"maintainer"`
	Client      ClientConfig      `koanf:"client"`
	Definitions DefinitionsConfig `koanf:"definitions"`
}

type DefinitionsConfig struct {
	Directory string `koanf:"directory"`
}

// ClientConfig holds the config for the client
type ClientConfig struct {
	// RefreshInterval specifies how often the client should refresh the lists.
	RefreshInterval time.Duration `koanf:"refresh_interval"`
}

// MaintainerConfig holds the config for the maintainer
type MaintainerConfig struct {
	// DefinitionIDs specifies which use case lists the maintainer serves.
	DefinitionIDs []string `koanf:"definition_ids"`
	// Directory is the directory where the maintainer stores the lists.
	Directory string `koanf:"directory"`
}

// DefaultConfig returns the default configuration.
func DefaultConfig() Config {
	return Config{
		Maintainer: MaintainerConfig{},
		Client:     ClientConfig{RefreshInterval: 5 * time.Minute},
	}
}

func (c Config) IsMaintainer() bool {
	return len(c.Maintainer.DefinitionIDs) > 0
}
