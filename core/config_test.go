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
	"github.com/stretchr/testify/require"
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
			cmd.Flags().AddFlagSet(serverFlagSet)
			cmd.Flags().AddFlagSet(testFlagSet())

			// load the testEngine
			system.RegisterEngine(testEngine)
			// Load the system
			require.NoError(t, system.Load(cmd.Flags()))
			system.Config.Datadir = t.TempDir()
			// Configure system and the engines
			assert.Nil(t, system.Configure())

			// expect the testEngine config to contain the default values
			assert.Equal(t, []string{"default", "default"}, testEngine.TestConfig.List)
		})

		t.Run("it replaces the default values with values from the configfile", func(t *testing.T) {
			os.Args = []string{"command", "--configfile", "test/config/testengine.yaml"}
			testEngine := &TestEngine{}
			system := NewSystem()
			system.Config.Datadir = t.TempDir()

			// create a dummy command with the serverFlagSet and the testEngine flagSet:
			cmd := &cobra.Command{}
			serverFlagSet := FlagSet()
			// this is done by the cobra command and may only be done once

			cmd.Flags().AddFlagSet(serverFlagSet)
			cmd.Flags().AddFlagSet(testFlagSet())

			assert.NoError(t, serverFlagSet.Parse(os.Args[1:]))

			// load the testEngine
			system.RegisterEngine(testEngine)
			// Load the system
			require.NoError(t, system.Load(cmd.Flags()))
			system.Config.Datadir = t.TempDir()
			// Configure system and the engines
			assert.Nil(t, system.Configure())

			assert.Equal(t, []string{"configfilevalue"}, testEngine.TestConfig.List)
		})
	})
}

func Test_loadConfigIntoStruct(t *testing.T) {
	t.Run("scalar values from env", func(t *testing.T) {
		t.Setenv("NUTS_E", "nvironment")
		flagSet := pflag.NewFlagSet("test", pflag.ContinueOnError)
		flagSet.String("f", "lag", "A great option")
		type Target struct {
			F string `koanf:"f"`
			E string `koanf:"e"`
		}
		var target Target
		configMap := koanf.New(defaultDelimiter)
		assert.NoError(t, loadFromFlagSet(configMap, flagSet))
		assert.NoError(t, loadFromEnv(configMap))
		err := loadConfigIntoStruct(&target, configMap)
		assert.NoError(t, err)
		assert.Equal(t, "lag", target.F)
		assert.Equal(t, "nvironment", target.E)
	})
	t.Run("support for listed values from env and CLI", func(t *testing.T) {
		t.Setenv("NUTS_LIST", ",a, b, c,d,value-\\,-with-escaped-comma,")
		flagSet := pflag.NewFlagSet("test", pflag.ContinueOnError)
		type Target struct {
			List []string `koanf:"list"`
		}
		var target Target
		configMap := koanf.New(defaultDelimiter)
		assert.NoError(t, loadFromFlagSet(configMap, flagSet))
		assert.NoError(t, loadFromEnv(configMap))
		err := loadConfigIntoStruct(&target, configMap)
		assert.NoError(t, err)
		assert.Equal(t, []string{"", "a", "b", "c", "d", "value-,-with-escaped-comma", ""}, target.List)
	})
}

func TestServerConfig_Load(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		cmd := &cobra.Command{}
		cmd.Flags().AddFlagSet(FlagSet())
		config := NewServerConfig()
		assert.NoError(t, config.Load(cmd.Flags()))
	})
	t.Run("error - secret (token) password set on commandline", func(t *testing.T) {
		cmd := &cobra.Command{}
		cmd.Flags().String("vault.token", "", "")
		cmd.Flags().Parse([]string{"command", "--vault.token=secret"})
		config := NewServerConfig()

		err := config.Load(cmd.Flags())

		assert.EqualError(t, err, "flag vault.token is a secret, please set it in the config file or environment variable to avoid leaking it")
	})
	t.Run("error - secret (password) password set on commandline", func(t *testing.T) {
		cmd := &cobra.Command{}
		cmd.Flags().String("database.password", "", "")
		cmd.Flags().Parse([]string{"command", "--database.password=secret"})
		config := NewServerConfig()

		err := config.Load(cmd.Flags())

		assert.EqualError(t, err, "flag database.password is a secret, please set it in the config file or environment variable to avoid leaking it")
	})
}

func Test_loadFromFile(t *testing.T) {
	t.Run("ok - no file path provided", func(t *testing.T) {
		assert.NoError(t, loadFromFile(koanf.New(defaultDelimiter), ""))

	})
	t.Run("ok - file exists", func(t *testing.T) {
		assert.NoError(t, loadFromFile(koanf.New(defaultDelimiter), "test/config/http.yaml"))
	})
	t.Run("ok - default file does not exists", func(t *testing.T) {
		assert.NoError(t, loadFromFile(koanf.New(defaultDelimiter), defaultConfigFile))
	})

	t.Run("error - custom file does not exists", func(t *testing.T) {
		assert.EqualError(t, loadFromFile(koanf.New(defaultDelimiter), "nonexisting-config.yaml"), "unable to load config file: open nonexisting-config.yaml: no such file or directory")
	})

	t.Run("error - invalid config file contents", func(t *testing.T) {
		assert.EqualError(t, loadFromFile(koanf.New(defaultDelimiter), "test/config/corrupt.yaml"), "unable to load config file: yaml: line 1: did not find expected ',' or '}'")
	})
}
