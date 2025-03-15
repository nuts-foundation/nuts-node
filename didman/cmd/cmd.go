/*
 * Nuts node
 * Copyright (C) 2022 Nuts community
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

package cmd

import (
	"fmt"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/didman/api/v1"
	"github.com/nuts-foundation/nuts-node/json"
	"github.com/spf13/cobra"
)

// Cmd contains sub-commands for the remote client
func Cmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "didman",
		Short: "didman commands",
	}
	serviceCmds := &cobra.Command{
		Use:   "svc",
		Short: "service commands",
	}
	serviceCmds.AddCommand(addService())
	serviceCmds.AddCommand(deleteService())
	cmd.AddCommand(serviceCmds)
	return cmd
}

func addService() *cobra.Command {
	return &cobra.Command{
		Use:   "add [DID] [type] [endpoint]",
		Short: "Adds a service to a DID document.",
		Long: "Adds a service of the specified type to DID document identified by the given DID. " +
			"The given service endpoint can either be a string a compound service map in JSON format.",
		Args: cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientConfig := core.NewClientConfigForCommand(cmd)
			client := httpClient(clientConfig)

			targetDID := args[0]
			serviceType := args[1]
			serviceEndpoint := args[2]
			compoundService := make(map[string]string, 0)
			var result interface{}

			err := json.Unmarshal([]byte(serviceEndpoint), &compoundService)
			if err == nil {
				// Compound service
				result, err = client.AddCompoundService(targetDID, serviceType, compoundService)
			} else {
				// string endpoint
				result, err = client.AddEndpoint(targetDID, serviceType, serviceEndpoint)
			}
			if err != nil {
				return fmt.Errorf("unable to register service: %w", err)
			}

			resultJSON, _ := json.MarshalIndent(result, "", "  ")
			cmd.Println(string(resultJSON))

			return nil
		},
	}
}

func deleteService() *cobra.Command {
	return &cobra.Command{
		Use:   "delete [DID] [type]",
		Short: "Deletes a service from a DID document.",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientConfig := core.NewClientConfigForCommand(cmd)
			client := httpClient(clientConfig)
			err := client.DeleteEndpointsByType(args[0], args[1])
			if err != nil {
				return fmt.Errorf("unable to delete service: %w", err)
			}
			cmd.Println("Service deleted")
			return nil
		},
	}
}

// httpClient creates a remote client
func httpClient(config core.ClientConfig) v1.HTTPClient {
	return v1.HTTPClient{
		ClientConfig: config,
	}
}
