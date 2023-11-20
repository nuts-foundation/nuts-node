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

package policy

import (
	"github.com/spf13/pflag"
)

// FlagSet contains flags relevant for JSON-LD
func FlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("policy", pflag.ContinueOnError)
	flagSet.String("policy.directory", "", "Directory to read policy files from. Policy files are JSON files that contain a scope to PresentationDefinition mapping. Mutual exclusive with policy.address.")
	flagSet.String("policy.address", "", "The address of a remote policy server. Mutual exclusive with policy.directory.")
	return flagSet
}
