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

package cmd

import (
	"github.com/nuts-foundation/nuts-node/golden_hammer"
	"github.com/spf13/pflag"
)

// FlagSet contains flags relevant for the VDR instance
func FlagSet() *pflag.FlagSet {
	defs := golden_hammer.DefaultConfig()
	flagSet := pflag.NewFlagSet("goldenhammer", pflag.ContinueOnError)
	flagSet.Bool("goldenhammer.enabled", defs.Enabled, "Whether to enable automatically fixing DID documents with the required endpoints.")
	flagSet.Duration("goldenhammer.interval", defs.Interval, "The interval in which to check for DID documents to fix.")

	// Server-to-Server OpenID4VCI-related functionality that will probably go away soon.
	// Should not be relied on.
	flagSet.VisitAll(func(flag *pflag.Flag) {
		_ = flagSet.MarkHidden(flag.Name)
	})
	return flagSet
}
