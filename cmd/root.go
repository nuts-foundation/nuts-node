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
	"github.com/nuts-foundation/nuts-node/auth"
	authExperimentalAPI "github.com/nuts-foundation/nuts-node/auth/api/experimental"
	authIrmaAPI "github.com/nuts-foundation/nuts-node/auth/api/irma"
	authV1API "github.com/nuts-foundation/nuts-node/auth/api/v0"
	authCmd "github.com/nuts-foundation/nuts-node/auth/cmd"
	"io"
	"os"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	cryptoApi "github.com/nuts-foundation/nuts-node/crypto/api/v1"
	cryptoCmd "github.com/nuts-foundation/nuts-node/crypto/cmd"
	"github.com/nuts-foundation/nuts-node/network"
	networkApi "github.com/nuts-foundation/nuts-node/network/api/v1"
	networkCmd "github.com/nuts-foundation/nuts-node/network/cmd"
	"github.com/nuts-foundation/nuts-node/vcr"
	credApi "github.com/nuts-foundation/nuts-node/vcr/api/v1"
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
			cmd.PersistentFlags().AddFlagSet(core.FlagSet())
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
				logrus.Fatal(err)
			}
			if err := startServer(system); err != nil {
				logrus.Fatal(err)
			}
		},
	}
	addFlagSets(cmd)
	return cmd
}

func startServer(system *core.System) error {
	logrus.Info("Starting server with config:")
	logrus.Info(system.Config.PrintConfig())

	// check config on all engines
	if err := system.Configure(); err != nil {
		return err
	}

	// start engines
	if err := system.Start(); err != nil {
		return err
	}

	// init HTTP interfaces and routes
	echoServer := core.NewMultiEcho(system.EchoCreator, system.Config.HTTP.HTTPConfig)
	for httpGroup, httpConfig := range system.Config.HTTP.AltBinds {
		logrus.Infof("Binding /%s -> %s", httpGroup, httpConfig.Address)
		if err := echoServer.Bind(httpGroup, httpConfig); err != nil {
			return err
		}
	}
	for _, r := range system.Routers {
		r.Routes(echoServer)
	}

	defer func() {
		if err := system.Shutdown(); err != nil {
			logrus.Fatal(err)
		}
	}()
	if err := echoServer.Start(); err != nil {
		return err
	}
	return nil
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
	credentialInstance := vcr.NewVCRInstance()
	statusEngine := core.NewStatusEngine(system)
	metricsEngine := core.NewMetricsEngine()
	authInstance := auth.NewAuthInstance(auth.DefaultConfig(), vdrInstance, cryptoInstance)

	// add engine specific routes
	system.RegisterRoutes(&cryptoApi.Wrapper{C: cryptoInstance})
	system.RegisterRoutes(&networkApi.Wrapper{Service: networkInstance})
	system.RegisterRoutes(&vdrApi.Wrapper{VDR: vdrInstance})
	system.RegisterRoutes(&credApi.Wrapper{CR: credentialInstance.Registry(), R: credentialInstance})
	system.RegisterRoutes(statusEngine.(core.Routable))
	system.RegisterRoutes(metricsEngine.(core.Routable))
	system.RegisterRoutes(&authV1API.Wrapper{Auth: authInstance})
	system.RegisterRoutes(&authExperimentalAPI.Wrapper{Auth: authInstance})
	system.RegisterRoutes(&authIrmaAPI.Wrapper{Auth: authInstance})

	// Register engines
	system.RegisterEngine(statusEngine)
	system.RegisterEngine(metricsEngine)
	system.RegisterEngine(cryptoInstance)
	system.RegisterEngine(networkInstance)
	system.RegisterEngine(vdrInstance)
	system.RegisterEngine(credentialInstance)
	system.RegisterEngine(authInstance)
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
	cmd.PersistentFlags().AddFlagSet(core.FlagSet())
	cmd.PersistentFlags().AddFlagSet(cryptoCmd.FlagSet())
	cmd.PersistentFlags().AddFlagSet(networkCmd.FlagSet())
	cmd.PersistentFlags().AddFlagSet(vdrCmd.FlagSet())
	cmd.PersistentFlags().AddFlagSet(authCmd.FlagSet())
}
