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
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var reset = func() {
	os.Args = []string{}
}

func TestNewNutsConfig_Load(t *testing.T) {
	t.Run("sets defaults", func(t *testing.T) {
		cfg := NewServerConfig()
		cmd := testCommand()

		err := cfg.Load(cmd.Flags())
		require.NoError(t, err)

		assert.Equal(t, "info", cfg.Verbosity)
		assert.Equal(t, "text", cfg.LoggerFormat)
		assert.Equal(t, true, cfg.Strictmode)
	})

	t.Run("Sets global Env prefix", func(t *testing.T) {
		cfg := NewServerConfig()
		cmd := testCommand()
		t.Setenv("NUTS_KEY", "value")

		err := cfg.Load(cmd.Flags())
		require.NoError(t, err)

		if value := cfg.configMap.Get("key"); value != "value" {
			t.Errorf("Expected key to have [value], got [%v]", value)
		}
	})

	t.Run("Sets correct key replacer", func(t *testing.T) {
		cfg := NewServerConfig()
		cmd := testCommand()
		t.Setenv("NUTS_SUB_KEY", "value")

		cfg.Load(cmd.Flags())

		if value := cfg.configMap.Get("sub.key"); value != "value" {
			t.Errorf("Expected sub.key to have [value], got [%v]", value)
		}
	})

	t.Run("Ignores unknown flags when parsing", func(t *testing.T) {
		defer reset()
		os.Args = []string{"executable", "command", "--unknown", "value"}
		cfg := NewServerConfig()
		cmd := testCommand()

		err := cfg.Load(cmd.Flags())

		assert.NoError(t, err)
	})

	t.Run("Returns error for incorrect verbosity", func(t *testing.T) {
		defer reset()
		os.Args = []string{"command", "--verbosity", "hell"}
		cfg := NewServerConfig()
		cmd := testCommand()

		err := cfg.Load(cmd.Flags())

		assert.Error(t, err)
	})

	t.Run("Returns error for incorrect logger format", func(t *testing.T) {
		defer reset()
		os.Args = []string{"command", "--loggerformat", "fluffy"}
		cfg := NewServerConfig()
		cmd := testCommand()

		err := cfg.Load(cmd.Flags())

		assert.Error(t, err)
		assert.EqualError(t, err, "invalid formatter: 'fluffy'")
	})

	t.Run("Strict-mode is on by default", func(t *testing.T) {
		defer reset()
		os.Args = []string{"command"}
		cfg := NewServerConfig()
		cmd := testCommand()
		err := cfg.Load(cmd.Flags())
		assert.NoError(t, err)
		assert.True(t, cfg.Strictmode)
	})

	t.Run("Strict-mode can be turned on", func(t *testing.T) {
		defer reset()
		os.Args = []string{"command", "--strictmode"}
		cfg := NewServerConfig()
		cmd := testCommand()

		err := cfg.Load(cmd.Flags())

		assert.NoError(t, err)
		assert.True(t, cfg.Strictmode)
	})

	t.Run("error - incorrect yaml", func(t *testing.T) {
		defer reset()
		os.Args = []string{"command", "--configfile", "test/config/corrupt.yaml"}
		cfg := NewServerConfig()
		cmd := testCommand()

		err := cfg.Load(cmd.Flags())

		require.Error(t, err)
	})

	t.Run("ok - env overrides default flag", func(t *testing.T) {
		defer reset()
		os.Args = []string{"command", "some", "args"}
		t.Setenv("NUTS_VERBOSITY", "warn")
		cfg := NewServerConfig()
		cmd := testCommand()

		err := cfg.Load(cmd.Flags())

		require.NoError(t, err)

		assert.Equal(t, "warn", cfg.Verbosity)
	})
}

func TestNewNutsConfig_PrintConfig(t *testing.T) {
	cfg := NewServerConfig()
	fs := pflag.FlagSet{}
	fs.String("camelCaseKey", "value", "description")
	fs.String("redactedKey", "redacted-value", "description")
	cmd := testCommand()
	cmd.Flags().AddFlagSet(&fs)
	cfg.Load(cmd.Flags())

	t.Run("output contains key", func(t *testing.T) {
		bs := cfg.PrintConfig()
		assert.Contains(t, bs, "camelCaseKey")
	})
	t.Run("redacts secret keys", func(t *testing.T) {
		old := redactedConfigKeys
		defer func() {
			redactedConfigKeys = old
		}()
		redactedConfigKeys = []string{"redactedKey"}

		bs := cfg.PrintConfig()
		assert.Contains(t, bs, "redactedKey -> (redacted)")
		assert.NotContains(t, bs, "redacted-value")
	})
}

func TestNewNutsConfig_InjectIntoEngine(t *testing.T) {
	defer reset()

	cfg := NewServerConfig()

	cmd := testCommand()
	flagSet := pflag.NewFlagSet("dummy", pflag.ContinueOnError)
	flagSet.String("testengine.key", "", "")
	flagSet.String("testengine.sub.test", "", "")
	flagSet.String("testengine.subptr.test", "", "")

	err := flagSet.Parse([]string{"--testengine.key", "value", "--testengine.sub.test", "testvalue", "--testengine.subptr.test", "test2value"})
	assert.NoError(t, err)

	cmd.Flags().AddFlagSet(flagSet)

	in := &TestEngine{
		TestConfig: TestEngineConfig{},
	}

	t.Run("param is injected", func(t *testing.T) {
		err := cfg.Load(cmd.Flags())
		assert.NoError(t, err)

		err = cfg.InjectIntoEngine(in)
		require.NoError(t, err)

		assert.Equal(t, "value", in.TestConfig.Key)
	})

	t.Run("param is injected recursively", func(t *testing.T) {
		err := cfg.Load(cmd.Flags())
		assert.NoError(t, err)

		err = cfg.InjectIntoEngine(in)
		require.NoError(t, err)

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
		cfg.Load(cmd.Flags())

		file := resolveConfigFilePath(cmd.Flags())

		assert.Equal(t, "from_file.yaml", file)
	})

	t.Run("uses configfile from env variable", func(t *testing.T) {
		defer reset()

		t.Setenv("NUTS_CONFIGFILE", "from_env.yaml")
		file := resolveConfigFilePath(FlagSet())

		assert.Equal(t, "from_env.yaml", file)
	})
}

func testCommand() *cobra.Command {
	cmd := &cobra.Command{}
	fs := FlagSet()

	// this is done by the cobra command and may only be done once
	fs.Parse(os.Args)

	cmd.Flags().AddFlagSet(fs)
	return cmd
}

func TestTLSConfig_LoadCertificate(t *testing.T) {
	t.Run("error - cert file does not exist", func(t *testing.T) {
		cfg := *NewServerConfig()
		cfg.TLS.CertFile = "test/non-existent.pem"
		cfg.TLS.CertKeyFile = "test/non-existent.pem"
		certificate, err := cfg.TLS.LoadCertificate()

		assert.Empty(t, certificate)
		assert.EqualError(t, err, "unable to load node TLS certificate (certfile=test/non-existent.pem,certkeyfile=test/non-existent.pem): open test/non-existent.pem: no such file or directory")
	})
	t.Run("use of legacy properties", func(t *testing.T) {
		cfg := *NewServerConfig()
		cfg.LegacyTLS.CertFile = "test/non-existent.pem"
		cfg.LegacyTLS.CertKeyFile = "test/non-existent.pem"
		certificate, err := cfg.TLS.LoadCertificate()

		assert.Empty(t, certificate)
		assert.EqualError(t, err, "unable to load node TLS certificate (certfile=test/non-existent.pem,certkeyfile=test/non-existent.pem): open test/non-existent.pem: no such file or directory")
	})
}

func TestTLSConfig_LoadTrustStore(t *testing.T) {
	t.Run("error - file does not exist", func(t *testing.T) {
		cfg := *NewServerConfig()
		cfg.TLS.TrustStoreFile = "test/non-existent.pem"
		ts, err := cfg.TLS.LoadTrustStore()

		assert.Empty(t, ts)
		assert.EqualError(t, err, "unable to read trust store (file=test/non-existent.pem): open test/non-existent.pem: no such file or directory")
	})
	t.Run("use of legacy properties", func(t *testing.T) {
		cfg := *NewServerConfig()
		cfg.LegacyTLS.TrustStoreFile = "test/non-existent.pem"
		ts, err := cfg.TLS.LoadTrustStore()

		assert.Empty(t, ts)
		assert.EqualError(t, err, "unable to read trust store (file=test/non-existent.pem): open test/non-existent.pem: no such file or directory")
	})
}

func TestTLSConfig_GetCRLMaxValidityDays(t *testing.T) {
	t.Run("tls", func(t *testing.T) {
		cfg := *NewServerConfig()
		cfg.TLS.CRL.MaxValidityDays = 1
		assert.Equal(t, cfg.TLS.GetCRLMaxValidityDays(), 1)
	})
	t.Run("legacy", func(t *testing.T) {
		cfg := *NewServerConfig()
		cfg.TLS.CRL.MaxValidityDays = 1
		cfg.LegacyTLS.MaxCRLValidityDays = 5
		assert.Equal(t, cfg.TLS.GetCRLMaxValidityDays(), 5)
	})
}
