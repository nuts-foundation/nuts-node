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

package engine

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-network/pkg"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vdr"
	api "github.com/nuts-foundation/nuts-node/vdr/api/v1"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// registryClientCreator is a variable to aid testability
var registryClientCreator = vdr.RegistryInstance()

// NewRegistryEngine returns the core definition for the registry
func NewRegistryEngine() *core.Engine {
	r := vdr.RegistryInstance()

	return &core.Engine{
		Cmd:       cmd(),
		Configure: r.Configure,
		Config:    &r.Config,
		ConfigKey: "vdr",
		FlagSet:   flagSet(),
		Name:      pkg.ModuleName,
		Routes: func(router core.EchoRouter) {
			api.RegisterHandlers(router, &api.Wrapper{VDR: r})
		},
		Start:       r.Start,
		Shutdown:    r.Shutdown,
		Diagnostics: r.Diagnostics,
	}
}

func flagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("registry", pflag.ContinueOnError)

	defs := vdr.DefaultRegistryConfig()
	flagSet.String(vdr.ConfDataDir, defs.Datadir, fmt.Sprintf("Location of data files, default: %s", defs.Datadir))
	flagSet.String(vdr.ConfMode, defs.Mode, fmt.Sprintf("server or client, when client it uses the HTTPClient, default: %s", defs.Mode))
	flagSet.String(vdr.ConfAddress, defs.Address, fmt.Sprintf("Interface and port for http server to bind to, default: %s", defs.Address))
	flagSet.Int(vdr.ConfClientTimeout, defs.ClientTimeout, fmt.Sprintf("Time-out for the client in seconds (e.g. when using the CLI), default: %d", defs.ClientTimeout))

	return flagSet
}

func cmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vdr",
		Short: "Verifiable Data Registry commands",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "create-did",
		Short: "Registers a new DID",
		Args:  cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			client := httpClient()

			doc, err := client.Create()
			if err != nil {
				fmt.Printf("Failed to create DID: %s\n", err.Error())
				return nil
			}

			bytes, err := json.MarshalIndent(doc, "", "  ")
			if err != nil {
				fmt.Printf("Failed to display DID document: %s\n", err.Error())
				return nil
			}

			fmt.Printf("Created DID document: %v\n", string(bytes))
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "resolve [DID]",
		Short: "Resolve a DID document based on its DID",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client := httpClient()

			did, err := did.ParseDID(args[0])
			if err != nil {
				fmt.Printf("Failed to parse DID: %s\n", err.Error())
				return nil
			}

			doc, meta, err := client.Get(*did)
			if err != nil {
				fmt.Printf("Failed to resolve DID document: %s\n", err.Error())
				return nil
			}

			for _, o := range []interface{}{doc, meta} {
				bytes, err := json.MarshalIndent(o, "", "  ")
				if err != nil {
					fmt.Printf("Failed to display object: %s\n", err.Error())
					return nil
				}
				fmt.Printf("%s\n", string(bytes))
			}

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

func httpClient() api.HTTPClient {
	core.NutsConfig().ServerAddress()

	return api.HTTPClient{
		ServerAddress: core.NutsConfig().ServerAddress(),
		Timeout:       5 * time.Second,
	}
}
