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
	"encoding/json"
	"fmt"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/spf13/pflag"
	"strings"
	"time"

	"github.com/nuts-foundation/nuts-node/core"
	api "github.com/nuts-foundation/nuts-node/vcr/api/vcr/v2"

	"github.com/spf13/cobra"
)

// FlagSet contains flags relevant for the module
func FlagSet() *pflag.FlagSet {
	defs := vcr.DefaultConfig()
	flagSet := pflag.NewFlagSet("vcr", pflag.ContinueOnError)
	flagSet.String("vcr.openid4vci.definitionsdir", defs.OpenID4VCI.DefinitionsDIR, "Directory with the additional credential definitions the node could issue (experimental, may change without notice).")
	flagSet.Bool("vcr.openid4vci.enabled", defs.OpenID4VCI.Enabled, "Enable issuing and receiving credentials over OpenID4VCI.")
	flagSet.Duration("vcr.openid4vci.timeout", time.Second*30, "Time-out for OpenID4VCI HTTP client operations.")

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
	cmd.AddCommand(issueVC())
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

			clientConfig := core.NewClientConfigForCommand(cmd)
			err := httpClient(clientConfig).Trust(cType, issuer)
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

			clientConfig := core.NewClientConfigForCommand(cmd)
			if err := httpClient(clientConfig).Untrust(cType, issuer); err != nil {
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

			clientConfig := core.NewClientConfigForCommand(cmd)
			issuers, err := httpClient(clientConfig).Trusted(cType)
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

			clientConfig := core.NewClientConfigForCommand(cmd)

			issuers, err := httpClient(clientConfig).Untrusted(cType)
			if err != nil {
				return fmt.Errorf("unable to get list of untrusted issuers: %v", err)
			}

			cmd.Println(strings.Join(issuers, "\n"))
			return nil
		},
	}
}

func issueVC() *cobra.Command {
	var publish bool
	var visibilityStr string
	var expirationDate string
	result := &cobra.Command{
		Use:   "issue [context] [type] [issuer-did] [subject]",
		Short: "Issues a Verifiable Credential",
		Long: "Issues a Verifiable Credential as the given issuer (as DID). " +
			"The context must be a single JSON-LD context URI (e.g. '" + credential.NutsV1Context + "'). " +
			"The type must be a single VC type (not being VerifiableCredential). " +
			"The subject must be the credential subject in JSON format. " +
			"It prints the issued VC if successfully issued.",
		Example: `nuts vcr issue "` + credential.NutsV1Context + `" "NutsAuthorizationCredential" "did:nuts:1234" "{'id': 'did:nuts:4321', 'purposeOfUse': 'eOverdracht-sender', 'etc': 'etcetc'}"`,
		Args:    cobra.ExactArgs(4),
		RunE: func(cmd *cobra.Command, args []string) error {
			credentialSubject := make(map[string]interface{}, 0)
			if err := json.Unmarshal([]byte(args[3]), &credentialSubject); err != nil {
				return fmt.Errorf("invalid credential subject: %w", err)
			}
			request := api.IssueVCRequest{
				//Context:           &args[0],
				//Type:              args[1],
				Issuer:            args[2],
				CredentialSubject: credentialSubject,
				PublishToNetwork:  &publish,
			}
			// set @context
			if args[0] != "" {
				request.Context = new(api.IssueVCRequest_Context)
				if anyContexts := toAnyStrings(args[0]); len(anyContexts) > 1 {
					//return errors.New("only 1 @context supported")
					if err := request.Context.FromIssueVCRequestContext1(anyContexts); err != nil {
						return fmt.Errorf("invalid @context: %w", err)
					}
				} else {
					if err := request.Context.FromIssueVCRequestContext0(args[0]); err != nil {
						return fmt.Errorf("invalid @context: %w", err)
					}
				}
			}
			// set type
			if anyTypes := toAnyStrings(args[1]); len(anyTypes) > 1 {
				if err := request.Type.FromIssueVCRequestType1(anyTypes); err != nil {
					return fmt.Errorf("invalid credential type: %w", err)
				}
			} else {
				if err := request.Type.FromIssueVCRequestType0(args[1]); err != nil {
					return fmt.Errorf("invalid credential type: %w", err)
				}
			}

			if publish {
				visibility := api.IssueVCRequestVisibility(visibilityStr)
				request.Visibility = &visibility
			}
			if len(expirationDate) > 0 {
				request.ExpirationDate = &expirationDate
			}
			issuedVC, err := httpClient(core.NewClientConfigForCommand(cmd)).IssueVC(request)
			if err != nil {
				return err
			}
			formattedVC, _ := json.MarshalIndent(issuedVC, "", "  ")
			cmd.Println(string(formattedVC))
			return nil
		},
	}
	result.Flags().BoolVarP(&publish, "publish", "p", true, "Whether to publish the credential to the network.")
	result.Flags().StringVarP(&visibilityStr, "visibility", "v", "private", "Whether to publish the credential publicly ('public') or privately ('private').")
	result.Flags().StringVarP(&expirationDate, "expiration", "e", "", "Date in RFC3339 format when the VC expires.")
	return result
}

// toAnyStrings splits input at ',' and returns the resulting parts as []any
func toAnyStrings(input string) []any {
	parts := strings.Split(input, ",")
	anyParts := make([]any, len(parts))
	for i, part := range parts {
		anyParts[i] = any(part)
	}
	return anyParts
}

// httpClient creates a remote client
func httpClient(config core.ClientConfig) api.HTTPClient {
	return api.HTTPClient{
		ClientConfig: config,
	}
}
