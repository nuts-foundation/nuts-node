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

// Config holds all the configuration params
type Config struct {
	IrmaSchemeManager     string   `koanf:"auth.irma.schememanager"`
	IrmaAutoUpdateSchemas bool     `koanf:"auth.irma.autoupdateschemas"`
	HTTPTimeout           int      `koanf:"auth.http.timeout"`
	PublicURL             string   `koanf:"auth.publicurl"`
	ClockSkew             int      `koanf:"auth.clockskew"`
	ContractValidators    []string `koanf:"auth.contractvalidators"`
	CertFile              string   `koanf:"network.certfile"`
	CertKeyFile           string   `koanf:"network.certkeyfile"`
	TrustStoreFile        string   `koanf:"network.truststorefile"`
	MaxCRLValidityDays    int      `koanf:"network.maxcrlvaliditydays"`
}

// DefaultConfig returns an instance of Config with the default values.
func DefaultConfig() Config {
	return Config{
		IrmaSchemeManager:     "pbdf",
		IrmaAutoUpdateSchemas: true,
		HTTPTimeout:           30,
		ClockSkew:             5000,
		ContractValidators:    []string{"irma", "uzi", "dummy"},
	}
}

func (c Config) tlsEnabled() bool {
	return c.CertFile != "" || c.CertKeyFile != ""
}
