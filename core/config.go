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
	"os"
	"strings"

	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/posflag"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

const defaultPrefix = "NUTS_"
const defaultDelimiter = "."
const defaultConfigFile = "nuts.yaml"
const configFileFlag = "configfile"
const loggerLevelFlag = "verbosity"
const addressFlag = "address"
const defaultLogLevel = "info"
const defaultAddress = "localhost:1323"
const strictModeFlag = "strictmode"

// NutsGlobalConfig has global settings.
type NutsGlobalConfig struct {
	Address    string `koanf:"address"`
	Verbosity  string `koanf:"verbosity"`
	Strictmode bool   `koanf:"strictmode"`
	configMap  *koanf.Koanf
}

func NewNutsConfig() *NutsGlobalConfig {
	return &NutsGlobalConfig{
		configMap:  koanf.New(defaultDelimiter),
		Address:    defaultAddress,
		Verbosity:  defaultLogLevel,
		Strictmode: false,
	}
}

// load follows the load order of configfile, env vars and then commandline param
func (ngc *NutsGlobalConfig) Load(cmd *cobra.Command) (err error) {
	cmd.PersistentFlags().AddFlagSet(ngc.flagSet())

	ngc.configMap = koanf.New(defaultDelimiter)
	f := ngc.getConfigfile(cmd)

	// load file
	p := file.Provider(f)
	if err = ngc.configMap.Load(p, yaml.Parser()); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return
		}
	}

	// load env
	e := env.Provider(defaultPrefix, defaultDelimiter, func(s string) string {
		return strings.Replace(strings.ToLower(
			strings.TrimPrefix(s, defaultPrefix)), "_", defaultDelimiter, -1)
	})
	// errors can't occur for this provider
	_ = ngc.configMap.Load(e, nil)

	// load cmd params
	if len(os.Args) > 1 {
		_ = cmd.PersistentFlags().Parse(os.Args[1:])
	}
	// errors can't occur for this provider
	_ = ngc.configMap.Load(posflag.Provider(cmd.PersistentFlags(), defaultDelimiter, ngc.configMap), nil)

	// load into struct
	if err = ngc.configMap.Unmarshal("", ngc); err != nil {
		return
	}

	// initialize logger, verbosity flag needs to be available
	if _, err = log.ParseLevel(ngc.Verbosity); err != nil {
		return
	}

	return
}

// getConfigfile returns the configfile path in the following order: commandline param, env variable, default path
func (ngc *NutsGlobalConfig) getConfigfile(cmd *cobra.Command) string {
	k := koanf.New(defaultDelimiter)

	if len(os.Args) > 1 {
		_ = cmd.PersistentFlags().Parse(os.Args[1:])
	}

	// load cmd flags, without a parser, no error can be returned
	_ = k.Load(posflag.Provider(cmd.PersistentFlags(), defaultDelimiter, k), nil)
	if f := k.String(configFileFlag); f != "" {
		return f
	}

	// load env flags
	e := env.Provider(defaultPrefix, defaultDelimiter, func(s string) string {
		return strings.Replace(strings.ToLower(
			strings.TrimPrefix(s, defaultPrefix)), "_", defaultDelimiter, -1)
	})
	// can't return error
	_ = k.Load(e, nil)
	if f := k.String(configFileFlag); f != "" {
		return f
	}

	return defaultConfigFile
}

func (ngc *NutsGlobalConfig) flagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("config", pflag.ContinueOnError)
	flagSet.String(configFileFlag, "", "Nuts config file")
	flagSet.String(loggerLevelFlag, defaultLogLevel, "Log level (trace, debug, info, warn, error)")
	flagSet.String(addressFlag, defaultAddress, "Address and port the server will be listening to")
	flagSet.Bool(strictModeFlag, false, "When set, insecure settings are forbidden.")
	return flagSet
}

// PrintConfig return the current config in string form
func (ngc *NutsGlobalConfig) PrintConfig() string {
	return ngc.configMap.Sprint()
}

// InjectIntoEngine
func (ngc *NutsGlobalConfig) InjectIntoEngine(e *Engine) error {
	// ignore if no target for injection
	if e.Config != nil {
		return ngc.configMap.Unmarshal(e.ConfigKey, e.Config)
	}

	return nil
}

// RegisterFlags adds the flagSet of an engine to the commandline, flag names are prefixed if needed
// The passed command must be the root command not the engine.Cmd (unless they are the same)
func (ngc *NutsGlobalConfig) RegisterFlags(cmd *cobra.Command, e *Engine) {
	if e.FlagSet != nil {
		cmd.PersistentFlags().AddFlagSet(e.FlagSet)
	}
}
