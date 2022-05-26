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
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func Test_ListMerging(t *testing.T) {
	t.Run("list values", func(t *testing.T) {
		t.Run("without extra config options, it uses the default values", func(t *testing.T) {
			testEngine := &TestEngine{}
			system := NewSystem()

			// create a dummy command with the serverFlagSet and the testEngine flagSet:
			cmd := &cobra.Command{}
			serverFlagSet := FlagSet()
			cmd.PersistentFlags().AddFlagSet(serverFlagSet)
			cmd.PersistentFlags().AddFlagSet(testFlagSet())

			// load the testEngine
			system.RegisterEngine(testEngine)
			// Load the system
			if !assert.NoError(t, system.Load(cmd)) {
				return
			}
			// Configure system and the engines
			assert.Nil(t, system.Configure())

			// expect the testEngine config to contain the default values
			assert.Equal(t, []string{"default", "default"}, testEngine.TestConfig.List)
		})

		t.Run("it replaces the default values with values from the configfile", func(t *testing.T) {
			os.Args = []string{"command", "--configfile", "test/config/testengine.yaml"}
			testEngine := &TestEngine{}
			system := NewSystem()

			// create a dummy command with the serverFlagSet and the testEngine flagSet:
			cmd := &cobra.Command{}
			serverFlagSet := FlagSet()
			// this is done by the cobra command and may only be done once

			cmd.PersistentFlags().AddFlagSet(serverFlagSet)
			cmd.PersistentFlags().AddFlagSet(testFlagSet())

			assert.NoError(t, serverFlagSet.Parse(os.Args[1:]))

			// load the testEngine
			system.RegisterEngine(testEngine)
			// Load the system
			if !assert.NoError(t, system.Load(cmd)) {
				return
			}
			// Configure system and the engines
			assert.Nil(t, system.Configure())

			assert.Equal(t, []string{"configfilevalue"}, testEngine.TestConfig.List)
		})
	})
}

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
		configMap := &koanf.Koanf{}
		LoadConfigMap()
		loadConfig
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
