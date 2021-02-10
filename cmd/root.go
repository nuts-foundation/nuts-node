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
	"io"
	"os"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	cryptoApi "github.com/nuts-foundation/nuts-node/crypto/api/v1"
	cryptoCmd "github.com/nuts-foundation/nuts-node/crypto/cmd"
	"github.com/nuts-foundation/nuts-node/network"
	networkApi "github.com/nuts-foundation/nuts-node/network/api/v1"
	networkCmd "github.com/nuts-foundation/nuts-node/network/cmd"
	"github.com/nuts-foundation/nuts-node/vdr"
	vdrApi "github.com/nuts-foundation/nuts-node/vdr/api/v1"
	vdrCmd "github.com/nuts-foundation/nuts-node/vdr/cmd"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var stdOutWriter io.Writer = os.Stdout

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
		RunE: func(cmd *cobra.Command, args []string) error {
			// Load all config and add generic options
			if err := system.Load(cmd); err != nil {
				return err
			}
			cmd.Println("Current system config")
			cmd.Println(system.Config.PrintConfig())
			return nil
		},
	}
}

func createServerCommand(system *core.System) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Starts the Nuts server",
		Run: func(cmd *cobra.Command, args []string) {
			// Load all config and add generic options
			if err := system.Load(cmd); err != nil {
				panic(err)
			}

			logrus.Info("Starting server with config:")
			logrus.Info(system.Config.PrintConfig())

			// check config on all engines
			if err := system.Configure(); err != nil {
				logrus.Fatal(err)
			}

			// start engines
			if err := system.Start(); err != nil {
				logrus.Fatal(err)
			}

			// add routes
			echoServer := system.EchoCreator()
			for _, r := range system.Routers {
				r.Routes(echoServer)
			}

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
	addFlagSets(cmd)
	return cmd
}

// CreateCommand creates the command with all subcommands to run the system.
func CreateCommand(system *core.System) *cobra.Command {
	command := createRootCommand()
	command.SetOut(stdOutWriter)
	addSubCommands(system, command)
	return command
}

// CreateSystem creates the system and registers all default engines.
func CreateSystem() *core.System {
	system := core.NewSystem()
	// Create instances
	cryptoInstance := crypto.NewCryptoInstance()
	networkInstance := network.NewNetworkInstance(network.DefaultConfig(), cryptoInstance)
	vdrInstance := vdr.NewVDR(vdr.DefaultConfig(), cryptoInstance, networkInstance)

	// add engine specific routes
	system.RegisterRoutes(&cryptoApi.Wrapper{C: cryptoInstance})
	system.RegisterRoutes(&networkApi.Wrapper{Service: networkInstance})
	system.RegisterRoutes(&vdrApi.Wrapper{VDR: vdrInstance})

	// Register engines
	system.RegisterEngine(core.NewStatusEngine(system))
	system.RegisterEngine(core.NewMetricsEngine())
	system.RegisterEngine(cryptoInstance)
	system.RegisterEngine(networkInstance)
	system.RegisterEngine(vdrInstance)
	return system
}

// Execute registers all engines into the system and executes the root command.
func Execute(system *core.System) {
	command := CreateCommand(system)
	command.SetOut(stdOutWriter)

	// blocking main call
	command.Execute()
}

func addSubCommands(system *core.System, root *cobra.Command) {
	// Register client commands
	clientCommands := []*cobra.Command{
		cryptoCmd.Cmd(),
		networkCmd.Cmd(),
		vdrCmd.Cmd(),
	}
	clientFlags := core.ClientConfigFlags()
	for _, clientCommand := range clientCommands {
		clientCommand.PersistentFlags().AddFlagSet(clientFlags)
	}
	root.AddCommand(clientCommands...)
	// Register server commands
	root.AddCommand(createServerCommand(system))
	root.AddCommand(createPrintConfigCommand(system))
}

func addFlagSets(cmd *cobra.Command) {
	cmd.PersistentFlags().AddFlagSet(cryptoCmd.FlagSet())
	cmd.PersistentFlags().AddFlagSet(networkCmd.FlagSet())
	cmd.PersistentFlags().AddFlagSet(vdrCmd.FlagSet())
}
