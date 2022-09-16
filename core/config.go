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
	"fmt"
	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/posflag"
	"github.com/spf13/pflag"
	"os"
	"strings"
)

func loadConfigIntoStruct(target interface{}, configMap *koanf.Koanf) error {
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
		// return all errors but ignore the missing of the default config file
		if !errors.Is(err, os.ErrNotExist) || filepath != defaultConfigFile {
			return fmt.Errorf("unable to load config file: %w", err)
		}
	}
	return nil
}

// loadFromEnv loads the values from the environment variables into the configMap
func loadFromEnv(configMap *koanf.Koanf) error {
	e := env.ProviderWithValue(defaultEnvPrefix, defaultDelimiter, func(rawKey string, rawValue string) (string, interface{}) {
		key := strings.Replace(strings.ToLower(strings.TrimPrefix(rawKey, defaultEnvPrefix)), defaultEnvDelimiter, defaultDelimiter, -1)

		// Support multiple values separated by a comma
		values := splitWithEscaping(rawValue, configValueListSeparator, "\\")
		for i, value := range values {
			values[i] = strings.TrimSpace(value)
		}
		if len(values) == 1 {
			return key, values[0]
		}
		return key, values
	})
	return configMap.Load(e, nil)
}

// loadFromFlagSet loads the config values set in the command line options into the configMap.
// Als sets default value for all flags in the provided pflag.FlagSet if the values do not yet exist in the configMap.
func loadFromFlagSet(configMap *koanf.Koanf, flags *pflag.FlagSet) error {
	return configMap.Load(posflag.Provider(flags, defaultDelimiter, configMap), nil)
}

// splitWithEscaping see https://codereview.stackexchange.com/questions/259270/golang-splitting-a-string-by-a-separator-not-prefixed-by-an-escape-string/259382
func splitWithEscaping(s, separator, escape string) []string {
	s = strings.ReplaceAll(s, escape+separator, "\x00")
	tokens := strings.Split(s, separator)
	for i, token := range tokens {
		tokens[i] = strings.ReplaceAll(token, "\x00", separator)
	}
	return tokens
}
