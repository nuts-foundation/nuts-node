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

package pki

import (
	"github.com/spf13/pflag"
)

// FlagSet contains flags relevant for JSON-LD
func FlagSet() *pflag.FlagSet {
	defs := DefaultConfig()

	flagSet := pflag.NewFlagSet("pki", pflag.ContinueOnError)

	// Flags for denylist features
	flagSet.Int("pki.maxupdatefailhours", defs.MaxUpdateFailHours, "Maximum number of hours that a denylist update can fail")
	flagSet.Bool("pki.softfail", defs.Softfail, "Do not reject certificates if their revocation status cannot be established when softfail is true")
	flagSet.String("pki.denylist.trustedsigner", defs.Denylist.TrustedSigner, "Ed25519 public key (in PEM format) of the trusted signer for denylists")
	flagSet.String("pki.denylist.url", defs.Denylist.URL, "URL of PKI denylist (set to empty string to disable)")

	// Changing these config values is not recommended, and they are expected to almost always be the same value, so
	// do not show them in the config dump
	if err := flagSet.MarkHidden("pki.denylist.trustedsigner"); err != nil {
		panic(err)
	}
	if err := flagSet.MarkHidden("pki.denylist.url"); err != nil {
		panic(err)
	}
	return flagSet
}
