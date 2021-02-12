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
	"errors"
	"github.com/sirupsen/logrus"
	"os"
	"strings"

	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/posflag"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

const defaultConfigFile = "nuts.yaml"
const configFileFlag = "configfile"
const addressFlag = "address"
const datadirFlag = "datadir"
const defaultAddress = "localhost:1323"
const strictModeFlag = "strictmode"
const defaultStrictMode = false
const defaultDatadir = "./data"
const defaultLogLevel = "info"
const loggerLevelFlag = "verbosity"

// ServerConfig has global server settings.
type ServerConfig struct {
	Verbosity  string           `koanf:"verbosity"`
	Strictmode bool             `koanf:"strictmode"`
	Datadir    string           `koanf:"datadir"`
	HTTP       GlobalHTTPConfig `koanf:"http"`
	configMap  *koanf.Koanf
}

// GlobalHTTPConfig is the top-level config struct for HTTP interfaces.
type GlobalHTTPConfig struct {
	// HTTPConfig contains the config for the default HTTP interface.
	HTTPConfig `koanf:"default"`
	// AltBinds contains binds for alternative HTTP interfaces. The key of the map is the first part of the path
	// of the URL (e.g. `/internal/some-api` -> `internal`), the value is the HTTP interface it must be bound to.
	AltBinds map[string]HTTPConfig `koanf:"alt"`
}

// HTTPConfig contains configuration for an HTTP interface, e.g. address.
// It will probably contain security related properties in the future (TLS configuration, user/pwd requirements).
type HTTPConfig struct {
	// Address holds the interface address the HTTP service must be bound to, in the format of `interface:port` (e.g. localhost:5555).
	Address string `koanf:"address"`
}

// NewServerConfig creates a new config with some defaults
func NewServerConfig() *ServerConfig {
	return &ServerConfig{
		configMap:  koanf.New(defaultDelimiter),
		Verbosity:  defaultLogLevel,
		Strictmode: defaultStrictMode,
		Datadir:    defaultDatadir,
		HTTP: GlobalHTTPConfig{
			HTTPConfig: HTTPConfig{Address: defaultAddress},
			AltBinds:   map[string]HTTPConfig{},
		},
	}
}

// Load follows the load order of configfile, env vars and then commandline param
func (ngc *ServerConfig) Load(cmd *cobra.Command) (err error) {
	cmd.PersistentFlags().AddFlagSet(ngc.flagSet())

	ngc.configMap = koanf.New(defaultDelimiter)
	configFile := file.Provider(resolveConfigFile(cmd.PersistentFlags()))

	// load file
	if err = ngc.configMap.Load(configFile, yaml.Parser()); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return
		}
	}

	if err = loadConfigIntoStruct(cmd.PersistentFlags(), ngc, ngc.configMap); err != nil {
		return err
	}
	// Configure logging.
	// TODO: see #40
	lvl, err := logrus.ParseLevel(ngc.Verbosity)
	if err != nil {
		return err
	}
	logrus.SetLevel(lvl)
	return nil
}

// resolveConfigFile resolves the path of the config file using the following sources:
// 1. commandline params (using the given flags)
// 2. environment vars,
// 3. default location.
func resolveConfigFile(flags *pflag.FlagSet) string {
	k := koanf.New(defaultDelimiter)

	// load env flags
	e := env.Provider(defaultPrefix, defaultDelimiter, func(s string) string {
		return strings.Replace(strings.ToLower(
			strings.TrimPrefix(s, defaultPrefix)), "_", defaultDelimiter, -1)
	})
	// can't return error
	_ = k.Load(e, nil)

	if len(os.Args) > 1 {
		_ = flags.Parse(os.Args[1:])
	}

	// load cmd flags, without a parser, no error can be returned
	// this also loads the default flag value of nuts.yaml. So we need a way to know if it's overiden.
	_ = k.Load(posflag.Provider(flags, defaultDelimiter, k), nil)

	return k.String(configFileFlag)
}

func (ngc *ServerConfig) flagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("server", pflag.ContinueOnError)
	flagSet.String(configFileFlag, defaultConfigFile, "Nuts config file")
	flagSet.String(loggerLevelFlag, defaultLogLevel, "Log level (trace, debug, info, warn, error)")
	flagSet.String(addressFlag, defaultAddress, "Address and port the server will be listening to")
	flagSet.Bool(strictModeFlag, defaultStrictMode, "When set, insecure settings are forbidden.")
	flagSet.String(datadirFlag, defaultDatadir, "Directory where the node stores its files.")
	return flagSet
}

// PrintConfig return the current config in string form
func (ngc *ServerConfig) PrintConfig() string {
	return ngc.configMap.Sprint()
}

// InjectIntoEngine takes the loaded config and sets the engine's config struct
func (ngc *ServerConfig) InjectIntoEngine(e Injectable) error {
	return ngc.configMap.Unmarshal(e.ConfigKey(), e.Config())
}
