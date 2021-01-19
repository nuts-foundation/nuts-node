/*
 * Nuts registry
 * Copyright (C) 2020. Nuts community
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

package engine

import (
	"fmt"

	"github.com/nuts-foundation/nuts-network/pkg"
	"github.com/nuts-foundation/nuts-node/did/logging"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/did"
	api "github.com/nuts-foundation/nuts-node/did/api/v1"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// registryClientCreator is a variable to aid testability
var registryClientCreator = did.RegistryInstance()

// NewRegistryEngine returns the core definition for the registry
func NewRegistryEngine() *core.Engine {
	r := did.RegistryInstance()

	return &core.Engine{
		Cmd:       cmd(),
		Configure: r.Configure,
		Config:    &r.Config,
		ConfigKey: "registry",
		FlagSet:   flagSet(),
		Name:      pkg.ModuleName,
		Routes: func(router core.EchoRouter) {
			api.RegisterHandlers(router, &api.ApiWrapper{R: r})
		},
		Start:       r.Start,
		Shutdown:    r.Shutdown,
		Diagnostics: r.Diagnostics,
	}
}

func flagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("registry", pflag.ContinueOnError)

	defs := did.DefaultRegistryConfig()
	flagSet.String(did.ConfDataDir, defs.Datadir, fmt.Sprintf("Location of data files, default: %s", defs.Datadir))
	flagSet.String(did.ConfMode, defs.Mode, fmt.Sprintf("server or client, when client it uses the HttpClient, default: %s", defs.Mode))
	flagSet.String(did.ConfAddress, defs.Address, fmt.Sprintf("Interface and port for http server to bind to, default: %s", defs.Address))
	flagSet.Int(did.ConfClientTimeout, defs.ClientTimeout, fmt.Sprintf("Time-out for the client in seconds (e.g. when using the CLI), default: %d", defs.ClientTimeout))

	return flagSet
}

func cmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "registry",
		Short: "registry commands",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print the version number of the Nuts registry",
		Run: func(cmd *cobra.Command, args []string) {
			logging.Log().Errorf("version 0.0.0")
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "search [tags]",
		Short: "Find DIDs within the registry that have the given tags (comma-separated)",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			// split tags on comma and call Search

			//logging.Log().Errorf("Found %d organizations\n", len(os))
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "create-did",
		Short: "Registers a new DID",
		Args:  cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {

			// call Create

			//logging.Log().Info("DID registered.")
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "get [DID or tag]",
		Short: "Find a DID document based on its DID or tag",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {

			// call Get or GetByTag
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "tag DID [tags]",
		Short: "Replace the tags of the given DID document with the given tags (comma-separated)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {

			// call Tag
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "update DID [file]",
		Short: "Update a DID with the given DID document, this replaces the DID document. If no file is given, stdin is used",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {

			// read from file or stdin

			// call Update
			return nil
		},
	})

	return cmd
}
