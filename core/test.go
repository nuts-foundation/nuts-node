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
 */

package core

import (
	"errors"

	"github.com/spf13/pflag"
)

const testEngineName = "testengine"

// TestEngineConfig defines the configuration for the test engine
type TestEngineConfig struct {
	Key    string               `koanf:"key"`
	Sub    TestEngineSubConfig  `koanf:"sub"`
	SubPtr *TestEngineSubConfig `koanf:"subptr"`
	List   []string             `koanf:"list"`
}

// TestServerConfig returns a new ServerConfig with the given template applied.
func TestServerConfig(template ServerConfig) ServerConfig {
	config := NewServerConfig()
	// Most commonly used properties
	config.Datadir = template.Datadir
	config.Strictmode = template.Strictmode
	config.InternalRateLimiter = template.InternalRateLimiter
	return *config
}

// TestEngineSubConfig defines the `sub` configuration for the test engine
type TestEngineSubConfig struct {
	Test string `koanf:"test"`
}

type TestEngine struct {
	TestConfig    TestEngineConfig
	flagSet       *pflag.FlagSet
	ShutdownError bool
}

func testDefaultConfig() TestEngineConfig {
	return TestEngineConfig{List: []string{"default", "default"}, SubPtr: &TestEngineSubConfig{}}
}

// Start does test stuff
func (i *TestEngine) Start() error {
	return nil
}

// Shutdown does test stuff
func (i *TestEngine) Shutdown() error {
	if i.ShutdownError {
		return errors.New("failure")
	}
	return nil
}

func (i *TestEngine) Config() interface{} {
	return &i.TestConfig
}

func (i *TestEngine) FlagSet() *pflag.FlagSet {
	return i.flagSet
}

func (i *TestEngine) Name() string {
	return testEngineName
}

func testFlagSet() *pflag.FlagSet {
	flags := pflag.NewFlagSet(testEngineName, pflag.ContinueOnError)

	defs := testDefaultConfig()
	flags.StringSlice(testEngineName+".list", defs.List, "sets the values of list")
	flags.String(testEngineName+".key", defs.Key, "another flag")

	return flags
}
