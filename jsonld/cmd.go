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

package jsonld

import (
	"github.com/spf13/pflag"
)

// FlagSet contains flags relevant for VCR
func FlagSet() *pflag.FlagSet {
	defs := DefaultConfig()
	flagSet := pflag.NewFlagSet("jsonld", pflag.ContinueOnError)
	flagSet.StringSlice("jsonld.contexts.remoteallowlist", defs.Contexts.RemoteAllowList, "In strict mode, fetching external JSON-LD contexts is not allowed except for context-URLs listed here.")
	flagSet.StringToString("jsonld.contexts.localmapping", defs.Contexts.LocalFileMapping, "This setting allows mapping external URLs to local files for e.g. preventing external dependencies. These mappings have precedence over those in remoteallowlist.")
	return flagSet
}
