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
	"github.com/nuts-foundation/nuts-node/network/engine"
	vdr "github.com/nuts-foundation/nuts-node/vdr/engine"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"io"
	"os"
)

var stdOutWriter io.Writer = os.Stdout

// Allows overriding Echo server implementation to aid testing
var echoCreator = func() core.EchoServer {
	echo := echo.New()
	echo.HideBanner = true
	echo.Use(middleware.Logger())
	return echo
}

func createRootCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "nuts",
		Short: "Nuts executable which can be used to run the Nuts server or administer the remote Nuts server.",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.HelpFunc()(cmd, args)
		},
	}
}

func createPrintConfigCommand(system *core.System) *cobra.Command {
	return &cobra.Command{
		Use:   "config",
		Short: "Prints the current config",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Println(system.Config.PrintConfig())
		},
	}
}

func createServerCommand(system *core.System) *cobra.Command {
	return &cobra.Command{
		Use:   "server",
		Short: "Starts the Nuts server",
		Run: func(cmd *cobra.Command, args []string) {
			logrus.Info("Starting server with config:")
			logrus.Println(system.Config.PrintConfig())

			// check config on all engines
			if err := system.Configure(); err != nil {
				logrus.Fatal(err)
			}

			// start engines
			if err := system.Start(); err != nil {
				logrus.Fatal(err)
			}

			// start interfaces
			echoServer := echoCreator()
			system.VisitEngines(func(engine *core.Engine) {
				if engine.Routes != nil {
					engine.Routes(echoServer)
				}
			})

			defer func() {
				if err := system.Shutdown(); err != nil {
					logrus.Fatal(err)
				}
			}()
			if err := echoServer.Start(system.Config.Address); err != nil {
				logrus.Fatal(err)
			}
		},
	}
}

// CreateCommand creates the command with all subcommands to run the system.
func CreateCommand(system *core.System) *cobra.Command {
	command := createRootCommand()
	command.SetOut(stdOutWriter)
	addSubCommands(system, command)
	addFlagSets(system, command)
	return command
}

// CreateSystem creates the system and registers all default engines.
func CreateSystem() *core.System {
	system := core.NewSystem()
	// Register default engines
	system.RegisterEngine(core.NewStatusEngine(system))
	system.RegisterEngine(core.NewLoggerEngine())
	system.RegisterEngine(core.NewMetricsEngine())
	cryptoEngine, keyStore := crypto.NewCryptoEngine()
	system.RegisterEngine(cryptoEngine)
	networkEngine, networkInstance := engine.NewNetworkEngine(keyStore)
	system.RegisterEngine(networkEngine)
	system.RegisterEngine(vdr.NewVDREngine(keyStore, networkInstance))
	return system
}

func Execute() {
	system := CreateSystem()
	command := CreateCommand(system)
	command.SetOut(stdOutWriter)

	// Load all config and add generic options
	if err := system.Config.Load(command); err != nil {
		panic(err)
	}

	// Load config into engines
	injectConfig(system)

	// blocking main call
	command.Execute()
}

func addSubCommands(system *core.System, root *cobra.Command) {
	system.VisitEngines(func(engine *core.Engine) {
		if engine.Cmd != nil {
			root.AddCommand(engine.Cmd)
		}
	})
	root.AddCommand(createServerCommand(system))
	root.AddCommand(createPrintConfigCommand(system))
}

func injectConfig(system *core.System) {
	if err := system.VisitEnginesE(func(engine *core.Engine) error {
		return system.Config.InjectIntoEngine(engine)
	}); err != nil {
		logrus.Fatal(err)
	}
}

func addFlagSets(system *core.System, cmd *cobra.Command) {
	system.VisitEngines(func(engine *core.Engine) {
		system.Config.RegisterFlags(cmd, engine)
	})
}
