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
 */

package cmd

import (
	"github.com/nuts-foundation/nuts-node/usecase"
	"github.com/spf13/pflag"
)

// FlagSet returns the configuration flags for the module
func FlagSet() *pflag.FlagSet {
	flags := pflag.NewFlagSet("usecase", pflag.ContinueOnError)

	defs := usecase.DefaultConfig()
	flags.String("usecase.definitions.directory", defs.Definitions.Directory, "The directory which contains use case definitions to load for clients and/or maintainers.")
	flags.StringSlice("usecase.maintainer.definition_ids", defs.Maintainer.DefinitionIDs, "The definition IDs which the maintainer serves.")
	flags.String("usecase.maintainer.directory", defs.Maintainer.Directory, "The directory where the maintainer stores the lists.")

	return flags
}
