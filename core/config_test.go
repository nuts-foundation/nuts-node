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

func TestNutsGlobalConfig_Load(t *testing.T) {
	t.Run("sets defaults", func(t *testing.T) {
		cfg := NewNutsConfig()

		err := cfg.Load(&cobra.Command{})
		if !assert.NoError(t, err) {
			return
		}

		assert.Equal(t, defaultAddress, cfg.Address)
		assert.Equal(t, defaultLogLevel, cfg.Verbosity)
		assert.Equal(t, false, cfg.Strictmode)
	})

	t.Run("Sets global Env prefix", func(t *testing.T) {
		cfg := NewNutsConfig()
		os.Setenv("NUTS_KEY", "value")

		err := cfg.Load(&cobra.Command{})
		if !assert.NoError(t, err) {
			return
		}

		if value := cfg.configMap.Get("key"); value != "value" {
			t.Errorf("Expected key to have [value], got [%v]", value)
		}
	})

	t.Run("Sets correct key replacer", func(t *testing.T) {
		cfg := NewNutsConfig()
		os.Setenv("NUTS_SUB_KEY", "value")

		cfg.Load(&cobra.Command{})

		if value := cfg.configMap.Get("sub.key"); value != "value" {
			t.Errorf("Expected sub.key to have [value], got [%v]", value)
		}
	})
}

func TestNutsGlobalConfig_Load2(t *testing.T) {
	defer func() {
		os.Args = []string{"command"}
	}()

	t.Run("Ignores unknown flags when parsing", func(t *testing.T) {
		os.Args = []string{"executable", "command", "--unknown", "value"}
		cfg := NewNutsConfig()

		err := cfg.Load(&cobra.Command{})

		assert.NoError(t, err)
	})

	t.Run("Ignores --help as incorrect argument", func(t *testing.T) {
		os.Args = []string{"command", "--help"}
		cfg := NewNutsConfig()

		if err := cfg.Load(&cobra.Command{}); err != nil {
			t.Errorf("Expected no error, got %v", err)
		}
	})

	t.Run("Returns error for incorrect verbosity", func(t *testing.T) {
		os.Args = []string{"command", "--verbosity", "hell"}
		cfg := NewNutsConfig()

		err := cfg.Load(&cobra.Command{})

		assert.Error(t, err)
	})

	t.Run("Strict-mode is off by default", func(t *testing.T) {
		os.Args = []string{"command"}
		cfg := NewNutsConfig()
		err := cfg.Load(&cobra.Command{})
		assert.NoError(t, err)
		assert.False(t, cfg.Strictmode)
	})

	t.Run("Strict-mode can be turned on", func(t *testing.T) {
		os.Args = []string{"command", "--strictmode"}
		cfg := NewNutsConfig()

		err := cfg.Load(&cobra.Command{})

		assert.NoError(t, err)
		assert.True(t, cfg.Strictmode)
	})
}

func TestNutsGlobalConfig_PrintConfig(t *testing.T) {
	cfg := NewNutsConfig()
	fs := pflag.FlagSet{}
	fs.String("camelCaseKey", "value", "description")
	cmd := &cobra.Command{}
	cmd.PersistentFlags().AddFlagSet(&fs)
	cfg.Load(cmd)

	bs := cfg.PrintConfig()

	t.Run("output contains key", func(t *testing.T) {
		if strings.Index(bs, "camelCaseKey") == -1 {
			t.Error("Expected key to be in output")
		}
	})
}

func TestNutsGlobalConfig_RegisterFlags(t *testing.T) {
	t.Run("adds flags", func(t *testing.T) {
		e := &Engine{
			Cmd:     &cobra.Command{},
			FlagSet: pflag.NewFlagSet("dummy", pflag.ContinueOnError),
		}
		e.FlagSet.String("key", "", "")

		assert.False(t, e.Cmd.PersistentFlags().HasAvailableFlags())

		cfg := NewNutsConfig()
		cfg.RegisterFlags(e.Cmd, e)

		assert.True(t, e.Cmd.PersistentFlags().HasAvailableFlags())
	})
}

func TestNutsGlobalConfig_InjectIntoEngine(t *testing.T) {
	defer func() {
		os.Args = []string{"command"}
	}()

	os.Args = []string{"command", "--key", "value"}
	cfg := NewNutsConfig()

	t.Run("param is injected", func(t *testing.T) {
		c := struct {
			Key string `koanf:"key"`
		}{}
		e := &Engine{
			Config:  &c,
			Cmd:     &cobra.Command{},
			FlagSet: pflag.NewFlagSet("dummy", pflag.ContinueOnError),
		}
		e.FlagSet.String("key", "", "test")

		cfg.RegisterFlags(e.Cmd, e)
		cfg.Load(e.Cmd)
		cfg.InjectIntoEngine(e)

		assert.Equal(t, "value", c.Key)
	})
}
