/*
 * Nuts node
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
 */

package cmd

import (
	"github.com/spf13/pflag"
)

// FlagSet contains flags relevant for the engine
func FlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("storage", pflag.ContinueOnError)
	flagSet.String("storage.databases.bbolt.backup.directory", "", "Target directory for BBolt database backups.")
	flagSet.String("storage.databases.bbolt.backup.interval", "0", "Interval, formatted as Golang duration (e.g. 10m, 1h) at which BBolt database backups will be performed.")
	return flagSet
}
