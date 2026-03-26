/*
 * Copyright (C) 2021 Nuts community
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

package auth

import (
	"github.com/nuts-foundation/nuts-node/auth/services"
	"github.com/nuts-foundation/nuts-node/auth/services/dummy"
	"github.com/nuts-foundation/nuts-node/auth/services/selfsigned"
)

// Config holds all the configuration params
type Config struct {
	Irma                IrmaConfig `koanf:"irma"`
	HTTPTimeout         int        `koanf:"http.timeout"`
	ClockSkew           int        `koanf:"clockskew"`
	ContractValidators  []string   `koanf:"contractvalidators"`
	AccessTokenLifeSpan int        `koanf:"accesstokenlifespan"`
	// Deprecated: use OpenID4VP.Enabled and OpenID4VCI.Enabled instead
	AuthorizationEndpoint AuthorizationEndpointConfig `koanf:"authorizationendpoint"`
	OpenID4VP             OpenID4VPConfig             `koanf:"openid4vp"`
	OpenID4VCI            OpenID4VCIConfig            `koanf:"openid4vci"`
}

// AuthorizationEndpointConfig is deprecated. Use OpenID4VPConfig and OpenID4VCIConfig instead.
type AuthorizationEndpointConfig struct {
	// Enabled is a flag to enable or disable the v2 API's Authorization Endpoint (/authorize), used for:
	// - As OpenID4VP verifier: to authenticate clients (that initiate the Authorized Code flow) using OpenID4VP
	// - As OpenID4VP wallet: to authenticate verifiers using OpenID4VP
	// - As OpenID4VCI wallet: to support dynamic credential requests
	// Deprecated: use auth.openid4vp.enabled and auth.openid4vci.enabled instead.
	Enabled bool `koanf:"enabled"`
}

// OpenID4VPConfig holds configuration for the OpenID4VP protocol.
type OpenID4VPConfig struct {
	// Enabled controls whether OpenID4VP is enabled.
	// When enabled, the node acts as an OpenID4VP verifier and wallet:
	// - As OpenID4VP verifier: authenticate clients using OpenID4VP (Authorization Code Flow)
	// - As OpenID4VP wallet: authenticate verifiers using OpenID4VP
	Enabled bool `koanf:"enabled"`
}

// OpenID4VCIConfig holds configuration for the OpenID4VCI (client) protocol.
type OpenID4VCIConfig struct {
	// Enabled controls whether OpenID4VCI (client) is enabled.
	// When enabled, the node acts as an OpenID4VCI wallet client, supporting dynamic credential requests.
	Enabled bool `koanf:"enabled"`
}

type IrmaConfig struct {
	SchemeManager     string     `koanf:"schememanager"`
	AutoUpdateSchemas bool       `koanf:"autoupdateschemas"`
	CORS              CORSConfig `koanf:"cors"`
}

// CORSConfig contains configuration for Cross Origin Resource Sharing.
type CORSConfig struct {
	// Origin specifies the AllowOrigin option. If no origins are given CORS is considered to be disabled.
	Origin []string `koanf:"origin"`
}

// DefaultConfig returns an instance of Config with the default values.
func DefaultConfig() Config {
	return Config{
		Irma: IrmaConfig{
			SchemeManager:     "pbdf",
			AutoUpdateSchemas: true,
		},
		ClockSkew: 5000,
		ContractValidators: []string{
			string(services.IrmaFormat),
			dummy.ContractFormat,
			selfsigned.ContractFormat,
		},
		AccessTokenLifeSpan: 60, // seconds, as specced in RFC003
	}
}
