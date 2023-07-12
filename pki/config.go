/*
 * Nuts node
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

package pki

func DefaultConfig() Config {
	return Config{
		Denylist: DenylistConfig{
			URL:           "https://cdn.jsdelivr.net/gh/nuts-foundation/denylist@main/denylist/denylist.jws",
			TrustedSigner: "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAmKjcSOrKOJR2cYd6UNbemNeusvjs930Y4nCIZ1R2zCI=\n-----END PUBLIC KEY-----",
		},
		MaxUpdateFailHours: 4,
		Softfail:           true,
	}
}

// Config specifies configuration parameters for PKI functionality
type Config struct {
	// Denylist specifies config options for the PKI denylist, which acts as a global CRL
	Denylist DenylistConfig `koanf:"denylist"`

	// MaxUpdateFailHours specifies the maximum number of hours that a denylist update can fail
	MaxUpdateFailHours int `koanf:"maxupdatefailhours"`

	// Softfail still accepts connections if the revocation status of a certificate cannot be reliably established if set to true
	Softfail bool `koanf:"softfail"`
}

// DenylistConfig specifies the config structure for the crl/certificate blacklist module
type DenylistConfig struct {
	// URL specifies the URL where the certificate blacklist is downloaded
	URL string `koanf:"url"`

	// TrustedSigner specifies the PEM Ed25519 public key which must sign the blacklist
	TrustedSigner string `koanf:"trustedsigner"`
}
