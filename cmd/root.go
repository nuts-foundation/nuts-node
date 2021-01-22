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

package cmd

import (
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/nuts-foundation/nuts-node/core"
	crypto "github.com/nuts-foundation/nuts-node/crypto/engine"
	vdr "github.com/nuts-foundation/nuts-node/vdr/engine"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func createRootCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "nuts",
		Short: "The Nuts service executable",
		Run: func(cmd *cobra.Command, args []string) {
			cfg := core.NutsConfig()
			if cfg.Mode() != core.GlobalServerMode {
				logrus.Error("Please specify a sub command when running in CLI mode")
				_ = cmd.Help()
				return
			}
			// start interfaces
			echo := echo.New()
			echo.HideBanner = true
			echo.Use(middleware.Logger())

			for _, engine := range core.EngineCtl.Engines {
				if engine.Routes != nil {
					engine.Routes(echo)
				}
			}

			defer shutdownEngines()
			logrus.Fatal(echo.Start(cfg.ServerAddress()))
		},
	}
}

func CreateCommand() *cobra.Command {
	if core.EngineCtl.Engines == nil {
		registerEngines()
	}
	command := createRootCommand()
	addSubCommands(command)
	addFlagSets(command, core.NutsConfig())
	return command
}

func Execute() {
	command := CreateCommand()

	// Load global Nuts config
	cfg := core.NutsConfig()

	// Load all config and add generic options
	if err := cfg.Load(command); err != nil {
		panic(err)
	}

	// Load config into engines
	injectConfig(cfg)
	cfg.PrintConfig(logrus.StandardLogger())

	// check config on all engines
	configureEngines()

	// start engines
	startEngines()

	// blocking main call
	command.Execute()
}

func addSubCommands(root *cobra.Command) {
	for _, e := range core.EngineCtl.Engines {
		if e.Cmd != nil {
			root.AddCommand(e.Cmd)
		}
	}
}

func registerEngines() {
	core.RegisterEngine(core.NewStatusEngine())
	core.RegisterEngine(core.NewLoggerEngine())
	core.RegisterEngine(core.NewMetricsEngine())
	core.RegisterEngine(crypto.NewCryptoEngine())
	core.RegisterEngine(vdr.NewVDREngine())

}

func injectConfig(cfg *core.NutsGlobalConfig) {
	// loop through configs and call viper.Get prepended with engine ConfigKey, inject value into struct
	for _, e := range core.EngineCtl.Engines {
		if err := cfg.InjectIntoEngine(e); err != nil {
			logrus.Fatal(err)
		}
	}
}

func configureEngines() {
	for _, e := range core.EngineCtl.Engines {
		// only if Engine is dynamically configurable
		if e.Configure != nil {
			if err := e.Configure(); err != nil {
				logrus.Fatal(err)
			}
		}
	}
}

func addFlagSets(cmd *cobra.Command, cfg *core.NutsGlobalConfig) {
	for _, e := range core.EngineCtl.Engines {
		cfg.RegisterFlags(cmd, e)
	}
}

func startEngines() {
	for _, e := range core.EngineCtl.Engines {
		if e.Start != nil {
			if err := e.Start(); err != nil {
				logrus.Fatal(err)
			}
		}
	}
}

func shutdownEngines() {
	for _, e := range core.EngineCtl.Engines {
		if e.Shutdown != nil {
			if err := e.Shutdown(); err != nil {
				logrus.Error(err)
			}
		}
	}
}
