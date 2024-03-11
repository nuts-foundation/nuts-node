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
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"os"
	"path"
	"testing"
	"time"
)

func Test_GetAddress(t *testing.T) {
	t.Run("address has http prefix", func(t *testing.T) {
		t.Setenv("NUTS_ADDRESS", "https://localhost")
		cmd := &cobra.Command{}
		cmd.PersistentFlags().AddFlagSet(ClientConfigFlags())
		cfg := NewClientConfigForCommand(cmd)
		assert.Equal(t, "https://localhost", cfg.GetAddress())
	})
	t.Run("address has no http prefix", func(t *testing.T) {
		t.Setenv("NUTS_ADDRESS", "localhost")
		cmd := &cobra.Command{}
		cmd.PersistentFlags().AddFlagSet(ClientConfigFlags())
		cfg := NewClientConfigForCommand(cmd)
		assert.Equal(t, "http://localhost", cfg.GetAddress())
	})
}

func TestClientConfigFlags(t *testing.T) {
	oldArgs := os.Args
	os.Args = []string{"nuts"}
	defer func() {
		os.Args = oldArgs
	}()
	t.Run("no args set", func(t *testing.T) {
		flags := ClientConfigFlags()
		address, err := flags.GetString(clientAddressFlag)
		assert.NoError(t, err)
		duration, err := flags.GetDuration(clientTimeoutFlag)
		assert.NoError(t, err)
		assert.Equal(t, defaultAddress, address)
		assert.Equal(t, defaultClientTimeout.String(), duration.String())
	})

	t.Run("args set", func(t *testing.T) {
		args := []string{"nuts", "--" + clientAddressFlag + "=localhost:1111", "--" + clientTimeoutFlag + "=20ms"}

		flags := ClientConfigFlags()
		flags.Parse(args)
		address, err := flags.GetString(clientAddressFlag)
		assert.NoError(t, err)
		duration, err := flags.GetDuration(clientTimeoutFlag)
		assert.NoError(t, err)
		assert.Equal(t, "localhost:1111", address)
		assert.Equal(t, "20ms", duration.String())
	})
}

func TestNewClientConfigFromConfigMap(t *testing.T) {
	t.Run("it contains the default values", func(t *testing.T) {
		cmd := &cobra.Command{}
		cmd.Flags().AddFlagSet(ClientConfigFlags())
		clientConfig := NewClientConfigForCommand(cmd)
		assert.Equal(t, defaultClientTimeout, clientConfig.Timeout)
		assert.Equal(t, defaultAddress, clientConfig.Address)
		assert.Equal(t, "info", clientConfig.Verbosity)
	})

	t.Run("it uses configured values", func(t *testing.T) {
		cmd := &cobra.Command{}
		args := []string{"nuts", "--" + clientAddressFlag + "=localhost:1111", "--" + clientTimeoutFlag + "=20ms", "--" + ("verbosity") + "=foo"}
		flags := ClientConfigFlags()
		assert.NoError(t, flags.Parse(args))
		cmd.Flags().AddFlagSet(flags)
		configMap := koanf.New(defaultDelimiter)
		clientConfig := ClientConfig{}
		loadFromFlagSet(configMap, cmd.Flags())
		loadConfigIntoStruct(&clientConfig, configMap)
		duration, err := flags.GetDuration(clientTimeoutFlag)
		assert.NoError(t, err)
		assert.Equal(t, duration, clientConfig.Timeout)
		assert.Equal(t, "localhost:1111", clientConfig.Address)
		assert.Equal(t, "foo", clientConfig.Verbosity)
	})
}

func TestNewClientConfigForCommand(t *testing.T) {
	t.Run("default values", func(t *testing.T) {
		cmd := &cobra.Command{}
		cmd.Flags().AddFlagSet(ClientConfigFlags())
		cfg := NewClientConfigForCommand(cmd)

		assert.Equal(t, "localhost:8081", cfg.Address)
		assert.Equal(t, 10*time.Second, cfg.Timeout)
		assert.Equal(t, "info", cfg.Verbosity)
	})
}

func TestClientConfig_GetAuthToken(t *testing.T) {
	t.Run("not set", func(t *testing.T) {
		testDirectory := io.TestDirectory(t)
		userHomeDirFn = func() (string, error) {
			return testDirectory, nil
		}

		token, err := ClientConfig{}.GetAuthToken()

		assert.NoError(t, err)
		assert.Empty(t, token)
	})
	t.Run("set", func(t *testing.T) {
		token, err := ClientConfig{Token: "foo"}.GetAuthToken()

		assert.NoError(t, err)
		assert.Equal(t, "foo", token)
	})
	t.Run("set in config takes precedence over from disk", func(t *testing.T) {
		testDirectory := io.TestDirectory(t)
		userHomeDirFn = func() (string, error) {
			return testDirectory, nil
		}
		_ = os.WriteFile(path.Join(testDirectory, clientConfigFileName), []byte("from disk"), 0644)

		token, err := ClientConfig{Token: "set in config"}.GetAuthToken()

		assert.NoError(t, err)
		assert.Equal(t, "set in config", token)
	})
	t.Run("read from disk (explicitly set)", func(t *testing.T) {
		testDirectory := io.TestDirectory(t)
		fileName := path.Join(testDirectory, clientConfigFileName)
		_ = os.WriteFile(fileName, []byte("foo"), 0644)

		token, err := ClientConfig{TokenFile: fileName}.GetAuthToken()

		assert.NoError(t, err)
		assert.Equal(t, "foo", token)
	})
	t.Run("read from disk (fallback to home dir)", func(t *testing.T) {
		testDirectory := io.TestDirectory(t)
		userHomeDirFn = func() (string, error) {
			return testDirectory, nil
		}
		_ = os.WriteFile(path.Join(testDirectory, clientConfigFileName), []byte("foo"), 0644)

		token, err := ClientConfig{}.GetAuthToken()

		assert.NoError(t, err)
		assert.Equal(t, "foo", token)
	})
	t.Run("error - unable to read from disk (file is a directory)", func(t *testing.T) {
		testDirectory := io.TestDirectory(t)
		userHomeDirFn = func() (string, error) {
			return testDirectory, nil
		}
		_ = os.MkdirAll(path.Join(testDirectory, clientConfigFileName), os.ModePerm)

		token, err := ClientConfig{}.GetAuthToken()

		assert.ErrorContains(t, err, "unable to read auth token from file")
		assert.Empty(t, token)
	})
}
