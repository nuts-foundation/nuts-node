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

package cmd

import (
	"sort"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
)

func TestFlagSet(t *testing.T) {
	flags := FlagSet()

	var keys []string

	// Assert all start with module config key
	flags.VisitAll(func(flag *pflag.Flag) {
		keys = append(keys, flag.Name)
	})

	sort.Strings(keys)

	assert.Equal(t, []string{
		ConfEventsHostname,
		ConfEventsPort,
		ConfEventsStorageDir,
	}, keys)
}
