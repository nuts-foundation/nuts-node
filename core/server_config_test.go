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
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
)

var reset = func() {
	os.Args = []string{}
}

func TestNewNutsConfig_Load(t *testing.T) {
	t.Run("sets defaults", func(t *testing.T) {
		cfg := NewServerConfig()
		cmd := testCommand()

		err := cfg.Load(cmd)
		if !assert.NoError(t, err) {
			return
		}

		assert.Equal(t, defaultLogLevel, cfg.Verbosity)
		assert.Equal(t, defaultLoggerFormat, cfg.LoggerFormat)
		assert.Equal(t, defaultStrictMode, cfg.Strictmode)
		assert.Equal(t, defaultHTTPInterface, cfg.HTTP.Address)
		assert.Empty(t, cfg.HTTP.AltBinds)
	})

	t.Run("Sets global Env prefix", func(t *testing.T) {
		cfg := NewServerConfig()
		cmd := testCommand()
		os.Setenv("NUTS_KEY", "value")
		defer os.Unsetenv("NUTS_KEY")

		err := cfg.Load(cmd)
		if !assert.NoError(t, err) {
			return
		}

		if value := cfg.configMap.Get("key"); value != "value" {
			t.Errorf("Expected key to have [value], got [%v]", value)
		}
	})

	t.Run("Sets correct key replacer", func(t *testing.T) {
		cfg := NewServerConfig()
		cmd := testCommand()
		os.Setenv("NUTS_SUB_KEY", "value")
		defer os.Unsetenv("NUTS_SUB_KEY")

		cfg.Load(cmd)

		if value := cfg.configMap.Get("sub.key"); value != "value" {
			t.Errorf("Expected sub.key to have [value], got [%v]", value)
		}
	})

	t.Run("Ignores unknown flags when parsing", func(t *testing.T) {
		defer reset()
		os.Args = []string{"executable", "command", "--unknown", "value"}
		cfg := NewServerConfig()
		cmd := testCommand()

		err := cfg.Load(cmd)

		assert.NoError(t, err)
	})

	t.Run("Returns error for incorrect verbosity", func(t *testing.T) {
		defer reset()
		os.Args = []string{"command", "--verbosity", "hell"}
		cfg := NewServerConfig()
		cmd := testCommand()

		err := cfg.Load(cmd)

		assert.Error(t, err)
	})

	t.Run("Returns error for incorrect logger format", func(t *testing.T) {
		defer reset()
		os.Args = []string{"command", "--loggerformat", "fluffy"}
		cfg := NewServerConfig()
		cmd := testCommand()

		err := cfg.Load(cmd)

		assert.Error(t, err)
		assert.EqualError(t, err, "invalid formatter: 'fluffy'")
	})

	t.Run("Strict-mode is off by default", func(t *testing.T) {
		defer reset()
		os.Args = []string{"command"}
		cfg := NewServerConfig()
		cmd := testCommand()
		err := cfg.Load(cmd)
		assert.NoError(t, err)
		assert.False(t, cfg.Strictmode)
	})

	t.Run("Strict-mode can be turned on", func(t *testing.T) {
		defer reset()
		os.Args = []string{"command", "--strictmode"}
		cfg := NewServerConfig()
		cmd := testCommand()

		err := cfg.Load(cmd)

		assert.NoError(t, err)
		assert.True(t, cfg.Strictmode)
	})

	t.Run("alt http configuration", func(t *testing.T) {
		defer reset()
		os.Args = []string{"command", "--configfile", "test/config/http.yaml"}
		cfg := NewServerConfig()
		cmd := testCommand()

		err := cfg.Load(cmd)
		assert.Equal(t, cfg.HTTP.Address, "alternative:1323")
		assert.Len(t, cfg.HTTP.AltBinds, 2)
		assert.Equal(t, cfg.HTTP.AltBinds["internal"].Address, "localhost:1111")
		assert.Equal(t, cfg.HTTP.AltBinds["admin"].Address, "localhost:2222")

		assert.NoError(t, err)
	})

	t.Run("error - incorrect yaml", func(t *testing.T) {
		defer reset()
		os.Args = []string{"command", "--configfile", "test/config/corrupt.yaml"}
		cfg := NewServerConfig()
		cmd := testCommand()

		err := cfg.Load(cmd)

		if !assert.Error(t, err) {
			return
		}
	})

	t.Run("ok - env overrides default flag", func(t *testing.T) {
		defer reset()
		os.Args = []string{"command", "some", "args"}
		os.Setenv("NUTS_VERBOSITY", "warn")
		defer os.Unsetenv("NUTS_VERBOSITY")
		cfg := NewServerConfig()
		cmd := testCommand()

		err := cfg.Load(cmd)

		if !assert.NoError(t, err) {
			return
		}

		assert.Equal(t, "warn", cfg.Verbosity)
	})
}

func TestNewNutsConfig_PrintConfig(t *testing.T) {
	cfg := NewServerConfig()
	fs := pflag.FlagSet{}
	fs.String("camelCaseKey", "value", "description")
	cmd := testCommand()
	cmd.PersistentFlags().AddFlagSet(&fs)
	cfg.Load(cmd)

	bs := cfg.PrintConfig()

	t.Run("output contains key", func(t *testing.T) {
		if strings.Index(bs, "camelCaseKey") == -1 {
			t.Error("Expected camelCaseKey to be in output")
		}
	})
}

func TestNewNutsConfig_InjectIntoEngine(t *testing.T) {
	defer reset()

	cfg := NewServerConfig()

	cmd := testCommand()
	flagSet := pflag.NewFlagSet("dummy", pflag.ContinueOnError)
	flagSet.String("key", "", "")
	flagSet.String("sub.test", "", "")
	flagSet.String("subptr.test", "", "")

	err := flagSet.Parse([]string{"--key", "value", "--sub.test", "testvalue", "--subptr.test", "test2value"})
	assert.NoError(t, err)

	cmd.PersistentFlags().AddFlagSet(flagSet)

	in := &TestEngine{
		TestConfig: TestEngineConfig{},
	}

	t.Run("param is injected", func(t *testing.T) {
		err := cfg.Load(cmd)
		assert.NoError(t, err)

		err = cfg.InjectIntoEngine(in)
		if !assert.NoError(t, err) {
			return
		}

		assert.Equal(t, "value", in.TestConfig.Key)
	})

	t.Run("param is injected recursively", func(t *testing.T) {
		err := cfg.Load(cmd)
		assert.NoError(t, err)

		err = cfg.InjectIntoEngine(in)
		if !assert.NoError(t, err) {
			return
		}

		assert.Equal(t, "testvalue", in.TestConfig.Sub.Test)
		assert.Equal(t, "test2value", in.TestConfig.SubPtr.Test)
	})
}

func TestNewNutsConfig_resolveConfigFile(t *testing.T) {
	t.Run("uses configfile from cmd line param", func(t *testing.T) {
		defer reset()

		os.Args = []string{"executable", "command", "--configfile", "from_file.yaml"}
		cmd := testCommand()
		cfg := NewServerConfig()
		cfg.Load(cmd)

		file := resolveConfigFile(cmd.PersistentFlags())

		assert.Equal(t, "from_file.yaml", file)
	})

	t.Run("uses configfile from env variable", func(t *testing.T) {
		defer reset()

		os.Setenv("NUTS_CONFIGFILE", "from_env.yaml")
		defer os.Unsetenv("NUTS_CONFIGFILE")
		cmd := &cobra.Command{}
		cfg := NewServerConfig()
		cfg.Load(cmd)

		file := resolveConfigFile(cmd.PersistentFlags())

		assert.Equal(t, "from_env.yaml", file)
	})
}

func testCommand() *cobra.Command {
	cmd := &cobra.Command{}
	fs := FlagSet()

	// this is done by the cobra command and may only be done once
	fs.Parse(os.Args)

	cmd.PersistentFlags().AddFlagSet(fs)
	return cmd
}
