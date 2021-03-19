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
)

// Cmd contains sub-commands for the remote client
func Cmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "did",
		Short: "High-level DID operations",
	}
	cmd.AddCommand(enableBoltCommand())
	cmd.AddCommand(disableBoltCommand())
	return cmd
}

func enableBoltCommand() *cobra.Command {
	var propertiesAsString []string
	cmd := &cobra.Command{
		Use:   "enable-bolt [DID] [bolt]",
		Args:  cobra.ExactArgs(2),
		Short: "Enables a Bolt for a DID using the given properties (-p 'key=value')",
		RunE: func(cmd *cobra.Command, args []string) error {
			panic("implement me")
			//httpClient(cmd.PersistentFlags()).EnableBolt()
		},
	}
	cmd.Flags().StringSliceVarP(&propertiesAsString, "properties", "p", nil, "Properties for the bolt passed as key=value")
	return cmd
}

func disableBoltCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "disable-bolt [DID] [bolt]",
		Short: "Disables a Bolt for a DID",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			panic("implement me")
		},
	}
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
