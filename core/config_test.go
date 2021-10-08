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

package core

import (
	"github.com/knadh/koanf"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func Test_loadConfigIntoStruct(t *testing.T) {
	t.Run("scalar values from env", func(t *testing.T) {
		os.Setenv("NUTS_E", "nvironment")
		defer os.Unsetenv("NUTS_E")
		flagSet := pflag.NewFlagSet("test", pflag.ContinueOnError)
		flagSet.String("f", "lag", "A great option")
		type Target struct {
			F string `koanf:"f"`
			E string `koanf:"e"`
		}
		var target Target
		err := loadConfigIntoStruct(flagSet, &target, koanf.New(defaultDelimiter))
		assert.NoError(t, err)
		assert.Equal(t, "lag", target.F)
		assert.Equal(t, "nvironment", target.E)
	})
	t.Run("support for listed values from env and CLI", func(t *testing.T) {
		os.Setenv("NUTS_LIST", "a, b, c,d")
		defer os.Unsetenv("NUTS_LIST")
		flagSet := pflag.NewFlagSet("test", pflag.ContinueOnError)
		type Target struct {
			List []string `koanf:"list"`
		}
		var target Target
		err := loadConfigIntoStruct(flagSet, &target, koanf.New(defaultDelimiter))
		assert.NoError(t, err)
		assert.Equal(t, []string{"a", "b", "c", "d"}, target.List)
	})
}
