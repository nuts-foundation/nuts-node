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
	"fmt"
	"github.com/knadh/koanf/v2"
	"github.com/spf13/cobra"
	"os"
	"path"
	"strings"
	"time"

	"github.com/spf13/pflag"
)

const defaultClientTimeout = 10 * time.Second
const clientTimeoutFlag = "timeout"
const clientAddressFlag = "address"
const defaultAddress = "localhost:8081"
const clientConfigFileName = ".nuts-client.cfg"

// userHomeDirFn is settable for testing purposes
var userHomeDirFn = os.UserHomeDir

// ClientConfig has CLI client settings.
type ClientConfig struct {
	Address    string        `koanf:"address"`
	Strictmode bool          `koanf:"strictmode"`
	Timeout    time.Duration `koanf:"timeout"`
	Token      string        `koanf:"token"`
	TokenFile  string        `koanf:"token-file"`
	Verbosity  string        `koanf:"verbosity"`
}

// NewClientConfigForCommand loads all the values for a given command into the provided configMap.
// defaults < ENV < CLI. Does not load config from file.
func NewClientConfigForCommand(cmd *cobra.Command) ClientConfig {
	configMap := koanf.New(defaultDelimiter)
	if err := loadFromEnv(configMap); err != nil {
		panic(err)
	}

	// also sets defaults that aren't in configMap yet
	if err := loadFromFlagSet(configMap, cmd.Flags()); err != nil {
		panic(err)
	}

	cfg := ClientConfig{}
	if err := loadConfigIntoStruct(&cfg, configMap); err != nil {
		panic(err)
	}
	return cfg
}

// GetAddress normalizes and gets the address of the server
func (cfg ClientConfig) GetAddress() string {
	addr := cfg.Address
	if !strings.HasPrefix(addr, "http") {
		addr = "http://" + addr
	}
	return addr
}

// GetAuthToken returns the configured auth token. If not set, it tries to read it from the filesystem.
// If the client config file does not exist, it returns an empty string.
func (cfg ClientConfig) GetAuthToken() (string, error) {
	if len(cfg.Token) > 0 {
		return cfg.Token, nil
	}
	tokenFile := cfg.TokenFile
	mustExist := true
	if len(tokenFile) == 0 {
		// token-file not set, try to read from user home dir
		mustExist = false
		dir, err := userHomeDirFn()
		if err != nil {
			return "", fmt.Errorf("unable to read auth token from file: %w", err)
		}
		tokenFile = path.Join(dir, clientConfigFileName)
	}

	tokenFileData, err := os.ReadFile(tokenFile)
	if err == nil {
		return strings.TrimSpace(string(tokenFileData)), nil
	} else if mustExist || !os.IsNotExist(err) {
		return "", fmt.Errorf("unable to read auth token from file '%s': %w", tokenFile, err)
	}
	return "", nil
}

// ClientConfigFlags returns the flags for configuring the client config.
func ClientConfigFlags() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("client", pflag.ContinueOnError)
	flagSet.String(clientAddressFlag, defaultAddress, "Address of the node. Must contain at least host and port, URL scheme may be omitted. In that case it 'http://' is prepended.")
	flagSet.Duration(clientTimeoutFlag, defaultClientTimeout, "Client time-out when performing remote operations, such as '500ms' or '10s'. Refer to Golang's 'time.Duration' syntax for a more elaborate description of the syntax.")
	flagSet.String("verbosity", "info", "Log level (trace, debug, info, warn, error)")
	flagSet.String("token", "", "Token to be used for authenticating on the remote node. Takes precedence over 'token-file'.")
	flagSet.String("token-file", "", fmt.Sprintf("File from which the authentication token will be read. "+
		"If not specified it will try to read the token from the '%s' file in the user's home dir.", clientConfigFileName))
	return flagSet
}
