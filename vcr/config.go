/*
 * Nuts node
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

package vcr

import "time"

// ModuleName is the name of this module.
const ModuleName = "VCR"

// Config holds the config for the vcr engine
type Config struct {
	// OIDC4VCI holds the config for the OIDC4VCI credential issuer and wallet
	OIDC4VCI OIDC4VCIConfig `koanf:"oidc4vci"`
	// datadir holds the location the VCR files are stored
	datadir       string
	clientTimeout time.Duration
}

// OIDC4VCIConfig holds the config for the OIDC4VCI credential issuer and wallet
type OIDC4VCIConfig struct {
	// Enabled indicates if issuing and receiving credentials over OIDC4VCI is enabled
	Enabled bool `koanf:"enabled"`
}

// DefaultConfig returns a fresh Config filled with default values
func DefaultConfig() Config {
	return Config{}
}
