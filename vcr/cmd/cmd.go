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
 */

package cmd

import (
	"fmt"
	"github.com/nuts-foundation/nuts-node/vcr"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/nuts-foundation/nuts-node/core"
	api "github.com/nuts-foundation/nuts-node/vcr/api/v1"
)

// FlagSet contains flags relevant for VCR
func FlagSet() *pflag.FlagSet {
	defs := vcr.DefaultConfig()
	flagSet := pflag.NewFlagSet("vcr", pflag.ContinueOnError)
	flagSet.Bool("vcr.overrideissueallpublic", defs.OverrideIssueAllPublic, "Overrides the \"Public\" property of a credential when issuing credentials: " +
		"if set to true, all issued credentials are published as public credentials, regardless of whether they're actually marked as public.")
	return flagSet
}


// Cmd contains sub-commands for the remote client
func Cmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vcr",
		Short: "Verifiable Credential Registry commands",
	}

	cmd.AddCommand(trustCmd())

	cmd.AddCommand(untrustCmd())

	cmd.AddCommand(listTrustedCmd())

	cmd.AddCommand(listUntrustedCmd())

	return cmd
}

func trustCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "trust [type] [issuer DID]",
		Short: "Trust VCs of a certain credential type when published by the given issuer.",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			cType := args[0]
			issuer := args[1]

			err := httpClient(cmd.Flags()).Trust(cType, issuer)

			if err != nil {
				return fmt.Errorf("unable to trust issuer: %v", err)
			}
			cmd.Println(fmt.Sprintf("%s is now trusted as issuer of %s", issuer, cType))
			return nil
		},
	}
}

func untrustCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "untrust [type] [issuer DID]",
		Short: "Untrust VCs of a certain credential type when published by the given issuer.",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			cType := args[0]
			issuer := args[1]

			err := httpClient(cmd.Flags()).Untrust(cType, issuer)

			if err != nil {
				return fmt.Errorf("unable to untrust issuer: %v", err)
			}
			cmd.Println(fmt.Sprintf("%s is no longer trusted as issuer of %s", issuer, cType))
			return nil
		},
	}
}

func listTrustedCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list-trusted [type]",
		Short: "List trusted issuers for given credential type",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cType := args[0]

			issuers, err := httpClient(cmd.Flags()).Trusted(cType)
			if err != nil {
				return fmt.Errorf("unable to get list of trusted issuers: %v", err)
			}

			cmd.Println(strings.Join(issuers, "\n"))
			return nil
		},
	}
}

func listUntrustedCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list-untrusted [type]",
		Short: "List untrusted issuers for given credential type",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cType := args[0]

			issuers, err := httpClient(cmd.Flags()).Untrusted(cType)
			if err != nil {
				return fmt.Errorf("unable to get list of untrusted issuers: %v", err)
			}

			cmd.Println(strings.Join(issuers, "\n"))
			return nil
		},
	}
}

// httpClient creates a remote client
func httpClient(set *pflag.FlagSet) api.HTTPClient {
	config := core.NewClientConfig(set)
	return api.HTTPClient{
		ServerAddress: config.GetAddress(),
		Timeout:       config.Timeout,
	}
}
