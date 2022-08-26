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
	"context"
	"fmt"
	httpEngine "github.com/nuts-foundation/nuts-node/http"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/spf13/pflag"
	"io"
	"os"
	"runtime/pprof"

	"github.com/nuts-foundation/nuts-node/auth"
	authIrmaAPI "github.com/nuts-foundation/nuts-node/auth/api/irma"
	authAPI "github.com/nuts-foundation/nuts-node/auth/api/v1"
	authCmd "github.com/nuts-foundation/nuts-node/auth/cmd"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/core/status"
	"github.com/nuts-foundation/nuts-node/crypto"
	cryptoAPI "github.com/nuts-foundation/nuts-node/crypto/api/v1"
	cryptoCmd "github.com/nuts-foundation/nuts-node/crypto/cmd"
	"github.com/nuts-foundation/nuts-node/didman"
	didmanAPI "github.com/nuts-foundation/nuts-node/didman/api/v1"
	didmanCmd "github.com/nuts-foundation/nuts-node/didman/cmd"
	"github.com/nuts-foundation/nuts-node/events"
	eventsCmd "github.com/nuts-foundation/nuts-node/events/cmd"
	httpCmd "github.com/nuts-foundation/nuts-node/http/cmd"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/network"
	networkAPI "github.com/nuts-foundation/nuts-node/network/api/v1"
	networkCmd "github.com/nuts-foundation/nuts-node/network/cmd"
	storageCmd "github.com/nuts-foundation/nuts-node/storage/cmd"
	"github.com/nuts-foundation/nuts-node/vcr"
	credAPIv2 "github.com/nuts-foundation/nuts-node/vcr/api/v2"
	vcrCmd "github.com/nuts-foundation/nuts-node/vcr/cmd"
	"github.com/nuts-foundation/nuts-node/vdr"
	vdrAPI "github.com/nuts-foundation/nuts-node/vdr/api/v1"
	vdrCmd "github.com/nuts-foundation/nuts-node/vdr/cmd"
	"github.com/nuts-foundation/nuts-node/vdr/doc"
	"github.com/nuts-foundation/nuts-node/vdr/store"
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
			if err := system.Load(cmd.Flags()); err != nil {
				return err
			}
			cmd.Println("Current system config")
			cmd.Println(system.Config.PrintConfig())
			return nil
		},
	}
}

func createServerCommand(system *core.System) *cobra.Command {
	return &cobra.Command{
		Use:   "server",
		Short: "Starts the Nuts server",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Load all config and add generic options
			if err := system.Load(cmd.Flags()); err != nil {
				return err
			}
			if err := startServer(cmd.Context(), system); err != nil {
				return err
			}
			return nil
		},
	}
}

func startServer(ctx context.Context, system *core.System) error {
	logrus.Info("Starting server")
	logrus.Info(fmt.Sprintf("Build info: \n%s", core.BuildInfo()))
	logrus.Info(fmt.Sprintf("Config: \n%s", system.Config.PrintConfig()))

	// check config on all engines
	if err := system.Configure(); err != nil {
		return err
	}

	// enable CPU profile if needed
	if system.Config.CPUProfile != "" {
		if !system.Config.Strictmode {
			logrus.Debugf("Outputting profiling info to %s", system.Config.CPUProfile)
			f, err := os.Create(system.Config.CPUProfile)
			if err != nil {
				return err
			}
			pprof.StartCPUProfile(f)
			defer pprof.StopCPUProfile()
		} else {
			logrus.Warn("Ignoring CPU profile option, strictmode is enabled")
		}
	}

	// migrate DBs if needed
	if err := system.Migrate(); err != nil {
		return err
	}

	// register HTTP routes (lookup router in engines first)
	var router core.EchoRouter
	system.VisitEngines(func(curr core.Engine) {
		if instance, ok := curr.(*httpEngine.Engine); ok {
			router = instance.Router()
		}
	})
	for _, r := range system.Routers {
		r.Routes(router)
	}

	// start engines
	if err := system.Start(); err != nil {
		return err
	}

	// Wait until instructed to shut down when instructed through context cancellation (e.g. SIGINT signal or Echo server error/exit)
	<-ctx.Done()
	logrus.Info("Shutting down...")
	err := system.Shutdown()
	if err != nil {
		logrus.Errorf("Error shutting down system: %v", err)
	} else {
		logrus.Info("Shutdown complete. Goodbye!")
	}

	return err
}

// CreateCommand creates the command with all subcommands to run the system.
func CreateCommand(system *core.System) *cobra.Command {
	command := createRootCommand()
	command.SetOut(stdOutWriter)
	addSubCommands(system, command)
	return command
}

// CreateSystem creates the system and registers all default engines.
func CreateSystem(shutdownCallback context.CancelFunc) *core.System {
	system := core.NewSystem()

	// Create instances
	cryptoInstance := crypto.NewCryptoInstance()
	httpServerInstance := httpEngine.New(shutdownCallback, cryptoInstance)
	jsonld := jsonld.NewJSONLDInstance()
	storageInstance := storage.New()
	didStore := store.NewStore(storageInstance.GetProvider(vdr.ModuleName))
	keyResolver := doc.KeyResolver{Store: didStore}
	docResolver := doc.Resolver{Store: didStore}
	docFinder := doc.Finder{Store: didStore}
	eventManager := events.NewManager()
	networkInstance := network.NewNetworkInstance(network.DefaultConfig(), keyResolver, cryptoInstance, cryptoInstance, docResolver, docFinder, eventManager, storageInstance.GetProvider(network.ModuleName))
	vdrInstance := vdr.NewVDR(vdr.DefaultConfig(), cryptoInstance, networkInstance, didStore, eventManager)
	credentialInstance := vcr.NewVCRInstance(cryptoInstance, docResolver, keyResolver, networkInstance, jsonld, eventManager, storageInstance)
	didmanInstance := didman.NewDidmanInstance(docResolver, didStore, vdrInstance, credentialInstance, jsonld)
	authInstance := auth.NewAuthInstance(auth.DefaultConfig(), didStore, credentialInstance, cryptoInstance, didmanInstance, jsonld)
	statusEngine := status.NewStatusEngine(system)
	metricsEngine := core.NewMetricsEngine()

	// Register HTTP routes
	system.RegisterRoutes(&core.LandingPage{})
	system.RegisterRoutes(&cryptoAPI.Wrapper{C: cryptoInstance})
	system.RegisterRoutes(&networkAPI.Wrapper{Service: networkInstance})
	system.RegisterRoutes(&vdrAPI.Wrapper{VDR: vdrInstance, DocResolver: docResolver, DocManipulator: &doc.Manipulator{
		KeyCreator: cryptoInstance,
		Updater:    vdrInstance,
		Resolver:   docResolver,
	}})
	system.RegisterRoutes(&credAPIv2.Wrapper{VCR: credentialInstance, ContextManager: jsonld})
	system.RegisterRoutes(statusEngine.(core.Routable))
	system.RegisterRoutes(metricsEngine.(core.Routable))
	system.RegisterRoutes(&authAPI.Wrapper{Auth: authInstance, CredentialResolver: credentialInstance})
	system.RegisterRoutes(&authIrmaAPI.Wrapper{Auth: authInstance})
	system.RegisterRoutes(&didmanAPI.Wrapper{Didman: didmanInstance})

	// Register engines
	system.RegisterEngine(jsonld)
	system.RegisterEngine(eventManager)
	system.RegisterEngine(storageInstance)
	system.RegisterEngine(didStore)
	system.RegisterEngine(statusEngine)
	system.RegisterEngine(metricsEngine)
	system.RegisterEngine(cryptoInstance)
	// the order of the next 3 modules is fixed due to configure and start dependencies
	system.RegisterEngine(credentialInstance)
	system.RegisterEngine(networkInstance)
	system.RegisterEngine(vdrInstance)
	system.RegisterEngine(authInstance)
	system.RegisterEngine(didmanInstance)
	// HTTP engine MUST be registered last, because when started it dispatches HTTP calls to the registered routes.
	// Registering is last makes sure all engines are started and ready to accept requests.
	system.RegisterEngine(httpServerInstance)

	return system
}

// Execute registers all engines into the system and executes the root command.
func Execute(ctx context.Context, system *core.System) error {
	command := CreateCommand(system)
	command.SetOut(stdOutWriter)

	// blocking main call
	return command.ExecuteContext(ctx)
}

func addSubCommands(system *core.System, root *cobra.Command) {
	// Register client commands
	clientCommands := []*cobra.Command{
		status.Cmd(),
		networkCmd.Cmd(),
		vcrCmd.Cmd(),
		vdrCmd.Cmd(),
		didmanCmd.Cmd(),
	}
	clientFlags := core.ClientConfigFlags()
	for _, clientCommand := range clientCommands {
		clientCommand.PersistentFlags().AddFlagSet(clientFlags)
	}
	root.AddCommand(clientCommands...)

	// Register server commands
	serverCommands := []*cobra.Command{
		createServerCommand(system),
		createPrintConfigCommand(system),
		cryptoCmd.ServerCmd(),
		httpCmd.ServerCmd(),
	}
	flagSet := serverConfigFlags()
	registerFlags(serverCommands, flagSet)

	root.AddCommand(serverCommands...)
}

func registerFlags(cmds []*cobra.Command, flags *pflag.FlagSet) {
	for _, cmd := range cmds {
		cmd.Flags().AddFlagSet(flags)
		registerFlags(cmd.Commands(), flags)
	}
}

// serverConfigFlags returns the flagSet needed for the server command
func serverConfigFlags() *pflag.FlagSet {
	set := pflag.NewFlagSet("server", pflag.ContinueOnError)

	set.AddFlagSet(core.FlagSet())
	set.AddFlagSet(cryptoCmd.FlagSet())
	set.AddFlagSet(httpCmd.FlagSet())
	set.AddFlagSet(storageCmd.FlagSet())
	set.AddFlagSet(networkCmd.FlagSet())
	set.AddFlagSet(vdrCmd.FlagSet())
	set.AddFlagSet(jsonld.FlagSet())
	set.AddFlagSet(authCmd.FlagSet())
	set.AddFlagSet(eventsCmd.FlagSet())

	return set
}
