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
	"errors"
	"fmt"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"io"
	"os"
	"runtime/pprof"

	"github.com/nuts-foundation/nuts-node/auth"
	authAPIv1 "github.com/nuts-foundation/nuts-node/auth/api/auth/v1"
	authIAMAPI "github.com/nuts-foundation/nuts-node/auth/api/iam"
	authMeansAPI "github.com/nuts-foundation/nuts-node/auth/api/means/v1"
	authCmd "github.com/nuts-foundation/nuts-node/auth/cmd"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/core/status"
	"github.com/nuts-foundation/nuts-node/crypto"
	cryptoAPI "github.com/nuts-foundation/nuts-node/crypto/api/v1"
	cryptoCmd "github.com/nuts-foundation/nuts-node/crypto/cmd"
	"github.com/nuts-foundation/nuts-node/didman"
	didmanAPI "github.com/nuts-foundation/nuts-node/didman/api/v1"
	didmanCmd "github.com/nuts-foundation/nuts-node/didman/cmd"
	"github.com/nuts-foundation/nuts-node/discovery"
	discoveryAPI "github.com/nuts-foundation/nuts-node/discovery/api/v1"
	discoveryCmd "github.com/nuts-foundation/nuts-node/discovery/cmd"
	"github.com/nuts-foundation/nuts-node/events"
	eventsCmd "github.com/nuts-foundation/nuts-node/events/cmd"
	"github.com/nuts-foundation/nuts-node/golden_hammer"
	goldenHammerCmd "github.com/nuts-foundation/nuts-node/golden_hammer/cmd"
	httpEngine "github.com/nuts-foundation/nuts-node/http"
	httpCmd "github.com/nuts-foundation/nuts-node/http/cmd"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/network"
	networkAPI "github.com/nuts-foundation/nuts-node/network/api/v1"
	networkCmd "github.com/nuts-foundation/nuts-node/network/cmd"
	"github.com/nuts-foundation/nuts-node/pki"
	"github.com/nuts-foundation/nuts-node/policy"
	"github.com/nuts-foundation/nuts-node/storage"
	storageCmd "github.com/nuts-foundation/nuts-node/storage/cmd"
	"github.com/nuts-foundation/nuts-node/vcr"
	openid4vciAPI "github.com/nuts-foundation/nuts-node/vcr/api/openid4vci/v0"
	vcrAPI "github.com/nuts-foundation/nuts-node/vcr/api/vcr/v2"
	vcrCmd "github.com/nuts-foundation/nuts-node/vcr/cmd"
	"github.com/nuts-foundation/nuts-node/vdr"
	vdrAPI "github.com/nuts-foundation/nuts-node/vdr/api/v1"
	vdrAPIv2 "github.com/nuts-foundation/nuts-node/vdr/api/v2"
	vdrCmd "github.com/nuts-foundation/nuts-node/vdr/cmd"
	"github.com/nuts-foundation/nuts-node/vdr/didnuts"
	"github.com/nuts-foundation/nuts-node/vdr/didnuts/didstore"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
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
		Run: func(cmd *cobra.Command, args []string) {
			// Load all config and add generic options
			if err := system.Load(cmd.Flags()); err != nil {
				logrus.WithError(err).Fatal("Could not start the server")
			}
			if err := startServer(cmd.Context(), system); err != nil {
				logrus.WithError(err).Fatal("Could not start the server")
			}
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

	// register HTTP routes
	if http, ok := system.FindEngineByName("http").(*httpEngine.Engine); ok {
		for _, r := range system.Routers {
			r.Routes(http.Router())
		}
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
	pkiInstance := pki.New()
	cryptoInstance := crypto.NewCryptoInstance()
	httpServerInstance := httpEngine.New(shutdownCallback, cryptoInstance)
	jsonld := jsonld.NewJSONLDInstance()
	storageInstance := storage.New()
	didStore := didstore.New(storageInstance.GetProvider(vdr.ModuleName))
	eventManager := events.NewManager()
	networkInstance := network.NewNetworkInstance(network.DefaultConfig(), didStore, cryptoInstance, eventManager, storageInstance.GetProvider(network.ModuleName), pkiInstance)
	vdrInstance := vdr.NewVDR(cryptoInstance, networkInstance, didStore, eventManager, storageInstance)
	credentialInstance := vcr.NewVCRInstance(cryptoInstance, vdrInstance, networkInstance, jsonld, eventManager, storageInstance, pkiInstance)
	didmanInstance := didman.NewDidmanInstance(vdrInstance, credentialInstance, jsonld)
	discoveryInstance := discovery.New(storageInstance, credentialInstance, vdrInstance)
	authInstance := auth.NewAuthInstance(auth.DefaultConfig(), vdrInstance, credentialInstance, cryptoInstance, didmanInstance, jsonld, pkiInstance)
	statusEngine := status.NewStatusEngine(system)
	metricsEngine := core.NewMetricsEngine()
	goldenHammer := golden_hammer.New(vdrInstance, didmanInstance)
	policyInstance := policy.NewRouter(pkiInstance)

	// Register HTTP routes
	system.RegisterRoutes(&core.LandingPage{})
	system.RegisterRoutes(&cryptoAPI.Wrapper{C: cryptoInstance, K: resolver.DIDKeyResolver{Resolver: vdrInstance.Resolver()}})
	system.RegisterRoutes(&networkAPI.Wrapper{Service: networkInstance})
	system.RegisterRoutes(&vdrAPI.Wrapper{VDR: vdrInstance, DocManipulator: &didnuts.Manipulator{
		KeyCreator: cryptoInstance,
		Updater:    vdrInstance,
		Resolver:   vdrInstance.Resolver(),
	}})
	system.RegisterRoutes(&vdrAPIv2.Wrapper{VDR: vdrInstance})
	system.RegisterRoutes(&vcrAPI.Wrapper{VCR: credentialInstance, ContextManager: jsonld})
	system.RegisterRoutes(&openid4vciAPI.Wrapper{
		VCR:           credentialInstance,
		DocumentOwner: vdrInstance,
	})
	system.RegisterRoutes(statusEngine.(core.Routable))
	system.RegisterRoutes(metricsEngine.(core.Routable))
	system.RegisterRoutes(&authAPIv1.Wrapper{Auth: authInstance, CredentialResolver: credentialInstance})
	system.RegisterRoutes(authIAMAPI.New(authInstance, credentialInstance, vdrInstance, storageInstance, policyInstance, jsonld))
	system.RegisterRoutes(&authMeansAPI.Wrapper{Auth: authInstance})
	system.RegisterRoutes(&didmanAPI.Wrapper{Didman: didmanInstance})
	system.RegisterRoutes(&discoveryAPI.Wrapper{Server: discoveryInstance, Client: discoveryInstance})

	// Register engines
	// without dependencies
	system.RegisterEngine(pkiInstance)
	system.RegisterEngine(cryptoInstance)
	system.RegisterEngine(jsonld)
	system.RegisterEngine(storageInstance)
	system.RegisterEngine(statusEngine)
	system.RegisterEngine(metricsEngine)
	system.RegisterEngine(eventManager)
	// the order of the next 3 modules is fixed due to configure and start dependencies
	system.RegisterEngine(didStore)
	system.RegisterEngine(vdrInstance)
	system.RegisterEngine(credentialInstance)
	system.RegisterEngine(networkInstance)
	system.RegisterEngine(authInstance)
	system.RegisterEngine(discoveryInstance)
	system.RegisterEngine(didmanInstance)
	system.RegisterEngine(goldenHammer)
	system.RegisterEngine(policyInstance)
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
	for _, cmd := range clientCommands {
		registerClientErrorHandler(cmd)
	}

	clientFlags := core.ClientConfigFlags()
	registerFlags(clientCommands, clientFlags)

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

func registerClientErrorHandler(cmd *cobra.Command) {
	if cmd.RunE != nil {
		cmd.RunE = clientErrorHandler(cmd.RunE)
	}
	for _, subCmd := range cmd.Commands() {
		registerClientErrorHandler(subCmd)
	}
}

// CobraRunE defines the signature of a Cobra command that returns an error.
type CobraRunE func(cmd *cobra.Command, args []string) error

// ClientErrorHandler wraps a Cobra command in a wrapper that logs server error response bodies returned by the HTTP client.
// It is to be used in CLI commands that use the HTTP client to invoke APIs on the Nuts node.
func clientErrorHandler(command CobraRunE) CobraRunE {
	return func(cmd *cobra.Command, args []string) error {
		err := command(cmd, args)
		if err != nil {
			var serverError core.HttpError
			if errors.As(err, &serverError) && len(serverError.ResponseBody) > 0 {
				cmd.PrintErrln("Server returned:")
				cmd.PrintErrln(string(serverError.ResponseBody))
			}
		}
		return err
	}
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
	set.AddFlagSet(vcrCmd.FlagSet())
	set.AddFlagSet(jsonld.FlagSet())
	set.AddFlagSet(authCmd.FlagSet())
	set.AddFlagSet(eventsCmd.FlagSet())
	set.AddFlagSet(pki.FlagSet())
	set.AddFlagSet(goldenHammerCmd.FlagSet())
	set.AddFlagSet(discoveryCmd.FlagSet())
	set.AddFlagSet(policy.FlagSet())

	return set
}
