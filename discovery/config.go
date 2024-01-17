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

package discovery

import "time"

// Config holds the config of the module
type Config struct {
	Server      ServerConfig             `koanf:"server"`
	Client      ClientConfig             `koanf:"client"`
	Definitions ServiceDefinitionsConfig `koanf:"definitions"`
}

// ServiceDefinitionsConfig holds the config for loading Service Definitions.
type ServiceDefinitionsConfig struct {
	Directory string `koanf:"directory"`
}

// ServerConfig holds the config for the server
type ServerConfig struct {
	// DefinitionIDs specifies which use case lists the server serves.
	DefinitionIDs []string `koanf:"definition_ids"`
}

// ClientConfig holds the config for the client
type ClientConfig struct {
	// RefreshInterval specifies how often the client should refresh the Discovery Services.
	RefreshInterval time.Duration `koanf:"refresh_interval"`
	// RegistrationRefreshInterval specifies how often the client should refresh its registrations on Discovery Services.
	// At the same interval, failed registrations are refreshed.
	RegistrationRefreshInterval time.Duration `koanf:"registration_refresh_interval"`
}

// DefaultConfig returns the default configuration.
func DefaultConfig() Config {
	return Config{
		Server: ServerConfig{},
		Client: ClientConfig{
			RefreshInterval:             10 * time.Minute,
			RegistrationRefreshInterval: 10 * time.Minute,
		},
	}
}
