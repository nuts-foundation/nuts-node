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

package http

// DefaultConfig returns the default configuration for the HTTP engine.
func DefaultConfig() Config {
	return Config{
		Log: LogMetadataLevel,
		Internal: InternalConfig{
			Address: "127.0.0.1:8081",
		},
		Public: PublicConfig{
			Address: ":8080",
		},
	}
}

// Config is the top-level config struct for HTTP interfaces.
type Config struct {
	// Log specifies what should be logged of HTTP requests.
	Log      LogLevel       `koanf:"log"`
	Public   PublicConfig   `koanf:"public"`
	Internal InternalConfig `koanf:"internal"`
}

// PublicConfig contains the configuration for outside-facing HTTP endpoints.
type PublicConfig struct {
	// Address holds the interface address the HTTP service must be bound to, in the format of `interface:port` (e.g. localhost:5555).
	Address string `koanf:"address"`
}

// InternalConfig contains the configuration for internal HTTP endpoints.
type InternalConfig struct {
	// Address holds the interface address the HTTP service must be bound to, in the format of `interface:port` (e.g. localhost:5555).
	Address string `koanf:"address"`
	// Auth specifies what authentication is required when accessing this interface.
	Auth AuthConfig `koanf:"auth"`
}

// LogLevel specifies what to log for incoming/outgoing HTTP traffic.
type LogLevel string

const (
	// LogNothingLevel indicates nothing will be logged for incoming/outgoing HTTP traffic.
	LogNothingLevel LogLevel = "nothing"
	// LogMetadataLevel indicates that only metadata (HTTP URI, method, response code, etc) will be logged for incoming/outgoing HTTP traffic.
	LogMetadataLevel = "metadata"
	// LogMetadataAndBodyLevel indicates that metadata and full request/reply bodies will be logged for incoming/outgoing HTTP traffic.
	LogMetadataAndBodyLevel = "metadata-and-body"
)

// AuthType defines the type for authentication types constants.
type AuthType string

const (
	// BearerTokenAuth specifies that a legacy bearer token (v1) authentication is in use
	BearerTokenAuth AuthType = "token"

	// BearerTokenAuthV2 specifies the latest version of bearer token authention
	BearerTokenAuthV2 = "token_v2"
)

// AuthConfig contains the configuration for authentication for an HTTP interface.
type AuthConfig struct {
	// Type specifies the type of authentication required for the interface.
	Type AuthType `koanf:"type"`
	// AuthorizedKeysPath specifies the path to an authorized_keys file which specified the allowed signers for JWT tokens
	AuthorizedKeysPath string `koanf:"authorizedkeyspath"`
	// Audience specifies the expected aud value for JWT tokens. If left empty the system hostname is used.
	Audience string `koanf:"audience"`
}
