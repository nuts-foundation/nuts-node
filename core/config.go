/*
 * Nuts node
 * Copyright (C) 2022 Nuts community
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
	"strings"

	"github.com/knadh/koanf"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/posflag"
	"github.com/spf13/pflag"
)

const defaultPrefix = "NUTS_"
const defaultDelimiter = "."
const configValueListSeparator = ","

func loadConfigIntoStruct(flags *pflag.FlagSet, target interface{}, configMap *koanf.Koanf) error {
	// load env
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
	_ = configMap.Load(e, nil)

	// errors can't occur for this provider
	_ = configMap.Load(posflag.Provider(flags, defaultDelimiter, configMap), nil)

	// load into struct
	return configMap.UnmarshalWithConf("", target, koanf.UnmarshalConf{
		FlatPaths: false,
	})
}
