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
	Irma                IrmaConfig       `koanf:"irma"`
	HTTPTimeout         int              `koanf:"http.timeout"`
	ClockSkew           int              `koanf:"clockskew"`
	ContractValidators  []string         `koanf:"contractvalidators"`
	AccessTokenLifeSpan int              `koanf:"accesstokenlifespan"`
	OpenID4VCI          OpenID4VCIConfig `koanf:"openid4vci"`
	OpenID4VP           OpenID4VPConfig  `koanf:"openid4vp"`
}

type OpenID4VPConfig struct {
	// Enabled is a flag to enable or disable OpenID4VP support:
	// - As OpenID4VP verifier: to authenticate clients using OpenID4VP
	// - As OpenID4VP wallet: to respond to OpenID4VP requests to from OpenID4VP verifiers.
	Enabled bool `koanf:"enabled"`
}

type OpenID4VCIConfig struct {
	// Enabled is a flag to enable OpenID4VCI support.
	// If enabled, credential issuance can be requested for local wallets through OpenID4VCI.
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
