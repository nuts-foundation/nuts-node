/*
 * Nuts node
 * Copyright (C) 2021 Nuts community
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package core

import "github.com/spf13/pflag"

type TestModuleConfig struct {
	Key     string `koanf:"key"`
	Datadir string `koanf:"datadir"`
}

type TestModule struct {
	TestConfig TestModuleConfig
	flagSet    *pflag.FlagSet
}

func (i *TestModule) ConfigKey() string {
	return ""
}

func (i *TestModule) Config() interface{} {
	return &i.TestConfig
}

func (i *TestModule) FlagSet() *pflag.FlagSet {
	return i.flagSet
}

func (i *TestModule) Name() string {
	return "test"
}
