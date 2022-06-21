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
	"github.com/spf13/cobra"
	"strings"
	"time"

	"github.com/knadh/koanf"
	"github.com/spf13/pflag"
)

const defaultClientTimeout = 10 * time.Second
const clientTimeoutFlag = "timeout"
const clientAddressFlag = "address"
const defaultAddress = "localhost" + defaultHTTPInterface

// ClientConfig has CLI client settings.
type ClientConfig struct {
	Address   string        `koanf:"address"`
	Verbosity string        `koanf:"verbosity"`
	Timeout   time.Duration `koanf:"timeout"`
}

// NewClientConfigForCommand loads all the values for a given command into the provided configMap.
// It loads the default values and then (when defined) overwrites them respectively with values from
// environment variables and command line flags.
// env and command line args cannot throw errors
func NewClientConfigForCommand(cmd *cobra.Command) (ClientConfig, error) {
	configMap := koanf.New(defaultDelimiter)
	if err := loadDefaultsFromFlagset(configMap, cmd.Flags()); err != nil {
		return ClientConfig{}, err
	}

	if err := loadFromEnv(configMap); err != nil {
		return ClientConfig{}, err
	}

	if err := loadFromFlagSet(configMap, cmd.PersistentFlags()); err != nil {
		return ClientConfig{}, err
	}
	return newClientConfigFromConfigMap(configMap)
}

// newClientConfigFromConfigMap returns an initialized ClientConfig with values set from the provided configMap
func newClientConfigFromConfigMap(configMap *koanf.Koanf) (ClientConfig, error) {
	cfg := ClientConfig{}
	if err := configMap.UnmarshalWithConf("", &cfg, koanf.UnmarshalConf{
		FlatPaths: false,
	}); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// GetAddress normalizes and gets the address of the remote server
func (cfg ClientConfig) GetAddress() string {
	addr := cfg.Address
	if !strings.HasPrefix(addr, "http") {
		addr = "http://" + addr
	}
	return addr
}

// ClientConfigFlags returns the flags for configuring the client config.
func ClientConfigFlags() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("client", pflag.ContinueOnError)
	flagSet.String(clientAddressFlag, defaultAddress, "Address of the remote node. Must contain at least host and port, URL scheme may be omitted. In that case it 'http://' is prepended.")
	flagSet.Duration(clientTimeoutFlag, defaultClientTimeout, "Client time-out when performing remote operations, such as '500ms' or '10s'. Refer to Golang's 'time.Duration' syntax for a more elaborate description of the syntax.")
	flagSet.String(loggerLevelFlag, defaultLogLevel, "Log level (trace, debug, info, warn, error)")
	return flagSet
}
