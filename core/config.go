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
	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/posflag"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"os"
	"strings"
)

func loadConfigIntoStruct(flags *pflag.FlagSet, target interface{}, configMap *koanf.Koanf) error {
	// load into struct
	return configMap.UnmarshalWithConf("", target, koanf.UnmarshalConf{
		FlatPaths: false,
	})
}

func loadFromFile(configMap *koanf.Koanf, filepath string) error {
	if filepath == "" {
		return nil
	}
	configFileProvider := file.Provider(filepath)
	// load file
	if err := configMap.Load(configFileProvider, yaml.Parser()); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func loadFromEnv(configMap *koanf.Koanf) error {
	e := env.ProviderWithValue(defaultPrefix, defaultDelimiter, func(rawKey string, rawValue string) (string, interface{}) {
		key := strings.Replace(strings.ToLower(strings.TrimPrefix(rawKey, defaultPrefix)), "_", defaultDelimiter, -1)

		// Support multiple values separated by a comma
		if strings.Contains(rawValue, configValueListSeparator) {
			values := strings.Split(rawValue, configValueListSeparator)
			for i, value := range values {
				values[i] = strings.TrimSpace(value)
			}
			return key, values
		}

		// Just a single value
		return key, rawValue
	})
	// errors can't occur for this provider
	return configMap.Load(e, nil)
}

func loadDefaultsFromFlagset(configMap *koanf.Koanf, flags *pflag.FlagSet) error {
	return configMap.Load(posflag.Provider(flags, defaultDelimiter, configMap), nil)
}

func loadFromFlagSet(configMap *koanf.Koanf, flags *pflag.FlagSet) error {
	return configMap.Load(posflag.Provider(flags, defaultDelimiter, configMap), nil)
}

func LoadConfigMap(configMap *koanf.Koanf, cmd *cobra.Command) error {
	flags := cmd.Flags()
	if err := loadDefaultsFromFlagset(configMap, flags); err != nil {
		return err
	}

	if err := loadFromFile(configMap, resolveConfigFilePath(cmd.PersistentFlags())); err != nil {
		return err
	}

	if err := loadFromEnv(configMap); err != nil {
		return err
	}

	if err := loadFromFlagSet(configMap, cmd.PersistentFlags()); err != nil {
		return err
	}

	return nil
}
