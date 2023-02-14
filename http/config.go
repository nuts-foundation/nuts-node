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
		InterfaceConfig: InterfaceConfig{
			Address: ":1323",
			Log:     LogMetadataLevel,
		},
		AltBinds: map[string]InterfaceConfig{},
	}
}

// Config is the top-level config struct for HTTP interfaces.
type Config struct {
	// InterfaceConfig contains the config for the default HTTP interface.
	InterfaceConfig `koanf:"default"`
	// AltBinds contains binds for alternative HTTP interfaces. The key of the map is the first part of the path
	// of the URL (e.g. `/internal/some-api` -> `internal`), the value is the HTTP interface it must be bound to.
	AltBinds map[string]InterfaceConfig `koanf:"alt"`
}

// InterfaceConfig contains configuration for an HTTP interface, e.g. address.
// It will probably contain security related properties in the future (TLS configuration, user/pwd requirements).
type InterfaceConfig struct {
	// Address holds the interface address the HTTP service must be bound to, in the format of `interface:port` (e.g. localhost:5555).
	Address string `koanf:"address"`
	// CORS holds the configuration for Cross Origin Resource Sharing.
	CORS CORSConfig `koanf:"cors"`
	// Auth specifies what authentication is required when accessing this interface.
	Auth AuthConfig `koanf:"auth"`
	// TLSMode specifies whether TLS is enabled for this interface, and which flavor.
	TLSMode TLSMode `koanf:"tls"`
	// Log specifies what should be logged of HTTP requests.
	Log LogLevel `koanf:"log"`
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

// TLSMode defines the values for TLS modes
type TLSMode string

const (
	// TLSDisabledMode specifies that TLS is not enabled for this interface.
	TLSDisabledMode TLSMode = "disabled"
	// TLSServerCertMode specifies that TLS is enabled for this interface, but no client certificate is required.
	TLSServerCertMode TLSMode = "server"
	// TLServerClientCertMode specifies that TLS is enabled for this interface, and that it will require a client certificate.
	TLServerClientCertMode TLSMode = "server-client"
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
	Type               AuthType `koanf:"type"`
	// AuthorizedKeysPath specifies the path to an authorized_keys file which specified the allowed signers for JWT tokens
	AuthorizedKeysPath string   `koanf:"authorizedkeyspath"`
	// Audience specifies the expected aud value for JWT tokens. If left empty the system hostname is used.
	Audience           string   `koanf:"audience"`
}

// CORSConfig contains configuration for Cross Origin Resource Sharing.
type CORSConfig struct {
	// Origin specifies the AllowOrigin option. If no origins are given CORS is considered to be disabled.
	Origin []string `koanf:"origin"`
}

// Enabled returns whether CORS is enabled according to this configuration.
func (cors CORSConfig) Enabled() bool {
	return len(cors.Origin) > 0
}
