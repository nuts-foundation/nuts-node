/*
 * Nuts node
 * Copyright (C) 2021. Nuts community
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
	"github.com/nuts-foundation/nuts-node/core"
	v1 "github.com/nuts-foundation/nuts-node/didman/api/v1"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"strings"
)

// Cmd contains sub-commands for the remote client
func Cmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "did",
		Short: "High-level DID operations",
	}
	cmd.AddCommand(applyServiceTemplateCommand())
	cmd.AddCommand(unapplyServiceTemplateCommand())
	return cmd
}

func applyServiceTemplateCommand() *cobra.Command {
	var propertiesAsString []string
	cmd := &cobra.Command{
		Use:   "svc-apply [name] [controller DID] [subject DID]",
		Args:  cobra.ExactArgs(3),
		Short: "Applies a service template for a controller and subject DID using the given properties (-p 'key=value')",
		RunE: func(cmd *cobra.Command, args []string) error {
			template := args[0]
			controller := args[1]
			subject := args[2]
			return httpClient(cmd.PersistentFlags()).ApplyServiceTemplate(controller, subject, template, parseKeyValueProperties(propertiesAsString))
		},
	}
	cmd.Flags().StringSliceVarP(&propertiesAsString, "properties", "p", nil, "Properties for the bolt passed as key=value")
	return cmd
}

func unapplyServiceTemplateCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "svc-unapply [name] [controller DID] [subject DID]",
		Short: "Unapplies a service template for a controller and subject DID.",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			template := args[0]
			controller := args[1]
			subject := args[2]
			return httpClient(cmd.PersistentFlags()).UnapplyServiceTemplate(controller, subject, template)
		},
	}
}

func parseKeyValueProperties(propertiesAsString []string) map[string]string {
	properties := make(map[string]string, 0)
	for _, propAsString := range propertiesAsString {
		propParts := strings.SplitN(propAsString, "=", 2)
		if len(propParts) == 2 {
			properties[propParts[0]] = propParts[1]
		}
	}
	return properties
}

// httpClient creates a remote client
func httpClient(set *pflag.FlagSet) v1.HTTPClient {
	config := core.NewClientConfig()
	if err := config.Load(set); err != nil {
		logrus.Fatal(err)
	}
	return v1.HTTPClient{
		ServerAddress: config.GetAddress(),
		Timeout:       config.Timeout,
	}
}
