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
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/core"
	api "github.com/nuts-foundation/nuts-node/vdr/api/v1"
	apiv2 "github.com/nuts-foundation/nuts-node/vdr/api/v2"
	"github.com/nuts-foundation/nuts-node/vdr/didnuts"
	"github.com/nuts-foundation/nuts-node/vdr/management"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// FlagSet contains flags relevant for the VDR instance
func FlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("vdr", pflag.ContinueOnError)
	return flagSet
}

// Cmd contains sub-commands for the remote client
func Cmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vdr",
		Short: "Verifiable Data VDR commands",
	}

	cmd.AddCommand(createCmd())
	cmd.AddCommand(resolveCmd())
	cmd.AddCommand(conflictedCmd())
	cmd.AddCommand(updateCmd())
	cmd.AddCommand(deactivateCmd())
	cmd.AddCommand(addVerificationMethodCmd())
	cmd.AddCommand(deleteVerificationMethodCmd())
	cmd.AddCommand(addKeyAgreementKeyCmd())

	return cmd
}

func createCmd() *cobra.Command {
	// needs to be initialized for pflags, values will be overwritten with defaults from pflag
	var createRequest = api.DIDCreateRequest{
		VerificationMethodRelationship: api.VerificationMethodRelationship{
			AssertionMethod:      new(bool),
			Authentication:       new(bool),
			CapabilityDelegation: new(bool),
			CapabilityInvocation: new(bool),
			KeyAgreement:         new(bool),
		},
		Controllers: new([]string),
		SelfControl: new(bool),
	}
	// todo should become default
	var useV2 bool

	result := &cobra.Command{
		Use:   "create-did",
		Short: "Registers a new DID",
		Long:  "When using the V2 API, a did:web DID will be created. All the other options are ignored for did:web.",
		Args:  cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientConfig := core.NewClientConfigForCommand(cmd)
			var (
				doc *did.Document
				err error
			)
			if useV2 {
				doc, err = httpClientV2(clientConfig).Create(apiv2.CreateDIDOptions{})
			} else {
				doc, err = httpClient(clientConfig).Create(createRequest)
			}
			if err != nil {
				return fmt.Errorf("unable to create new DID: %v", err)
			}
			bytes, _ := json.MarshalIndent(doc, "", "  ")
			cmd.Println(string(bytes))
			return nil
		},
	}

	defs := didnuts.DefaultKeyFlags()
	setUsage := func(def bool, usage string) string {
		opposite := "enable"
		if def {
			opposite = "disable"
		}
		return fmt.Sprintf(usage, !def, opposite)
	}
	result.Flags().BoolVar(createRequest.AssertionMethod, "assertionMethod", defs.Is(management.AssertionMethodUsage), setUsage(defs.Is(management.AssertionMethodUsage), "Pass '%t' to %s assertionMethod capabilities."))
	result.Flags().BoolVar(createRequest.Authentication, "authentication", defs.Is(management.AuthenticationUsage), setUsage(defs.Is(management.AuthenticationUsage), "Pass '%t' to %s authentication capabilities."))
	result.Flags().BoolVar(createRequest.CapabilityDelegation, "capabilityDelegation", defs.Is(management.CapabilityDelegationUsage), setUsage(defs.Is(management.CapabilityDelegationUsage), "Pass '%t' to %s capabilityDelegation capabilities."))
	result.Flags().BoolVar(createRequest.CapabilityInvocation, "capabilityInvocation", defs.Is(management.CapabilityInvocationUsage), setUsage(defs.Is(management.CapabilityInvocationUsage), "Pass '%t' to %s capabilityInvocation capabilities."))
	result.Flags().BoolVar(createRequest.KeyAgreement, "keyAgreement", defs.Is(management.KeyAgreementUsage), setUsage(defs.Is(management.KeyAgreementUsage), "Pass '%t' to %s keyAgreement capabilities."))
	result.Flags().BoolVar(createRequest.SelfControl, "selfControl", true, setUsage(true, "Pass '%t' to %s DID Document control."))
	result.Flags().BoolVar(&useV2, "v2", false, "Pass 'true' to use the V2 API and create a did:web DID.")
	result.Flags().StringSliceVar(createRequest.Controllers, "controllers", []string{}, "Comma-separated list of DIDs that can control the generated DID Document.")

	return result
}

func updateCmd() *cobra.Command {
	return &cobra.Command{
		Use: "update [DID] [hash] [file]",
		Short: "Update a DID with the given DID document, this replaces the DID document. " +
			"If no file is given, a pipe is assumed. The hash is needed to prevent concurrent updates.",
		Args: cobra.RangeArgs(2, 3),
		RunE: func(cmd *cobra.Command, args []string) error {
			id := args[0]
			hash := args[1]

			var bytes []byte
			var err error
			if len(args) == 3 {
				// read from file
				bytes, err = os.ReadFile(args[2])
				if err != nil {
					return fmt.Errorf("failed to read file %s: %w", args[2], err)
				}
			} else {
				// read from stdin
				bytes, err = readFromStdin()
				if err != nil {
					return fmt.Errorf("failed to read from pipe: %w", err)
				}
			}

			// parse
			var didDoc did.Document
			if err = json.Unmarshal(bytes, &didDoc); err != nil {
				return fmt.Errorf("failed to parse DID document: %w", err)
			}

			clientConfig := core.NewClientConfigForCommand(cmd)
			if _, err = httpClient(clientConfig).Update(id, hash, didDoc); err != nil {
				return fmt.Errorf("failed to update DID document: %w", err)
			}

			cmd.Println("DID document updated")
			return nil
		},
	}
}

func resolveCmd() *cobra.Command {
	var printMetadata bool
	var printDocument bool
	result := &cobra.Command{
		Use:   "resolve [DID]",
		Short: "Resolve a DID document based on its DID",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientConfig := core.NewClientConfigForCommand(cmd)
			doc, meta, err := httpClient(clientConfig).Get(args[0])
			if err != nil {
				return fmt.Errorf("failed to resolve DID document: %v", err)
			}

			var toPrint []interface{}
			if !printMetadata && !printDocument {
				toPrint = append(toPrint, doc, meta)
			} else {
				if printDocument {
					toPrint = append(toPrint, doc)
				}
				if printMetadata {
					toPrint = append(toPrint, meta)
				}
			}
			for _, o := range toPrint {
				bytes, _ := json.MarshalIndent(o, "", "  ")
				cmd.Printf("%s\n", string(bytes))
			}

			return nil
		},
	}
	result.Flags().BoolVar(&printMetadata, "metadata", false, "Pass 'true' to only print the metadata (unless other flags are provided as well).")
	result.Flags().BoolVar(&printDocument, "document", false, "Pass 'true' to only print the document (unless other flags are provided as well).")
	return result
}

func conflictedCmd() *cobra.Command {
	var printMetadata bool
	var printDocument bool
	result := &cobra.Command{
		Use:   "conflicted",
		Short: "Print conflicted documents and their metadata",
		Args:  cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientConfig := core.NewClientConfigForCommand(cmd)
			conflictedDocs, err := httpClient(clientConfig).ConflictedDIDs()
			if err != nil {
				return fmt.Errorf("failed to find conflicted documents: %v", err)
			}

			if !printMetadata && !printDocument {
				printMetadata = true
				printDocument = true
			}

			for _, doc := range conflictedDocs {
				if printDocument {
					bytes, _ := json.MarshalIndent(doc.Document, "", "  ")
					cmd.Printf("%s\n", string(bytes))
				}
				if printMetadata {
					bytes, _ := json.MarshalIndent(doc.DocumentMetadata, "", "  ")
					cmd.Printf("%s\n", string(bytes))
				}
			}

			return nil
		},
	}
	result.Flags().BoolVar(&printMetadata, "metadata", false, "Pass 'true' to only print the metadata (unless other flags are provided as well).")
	result.Flags().BoolVar(&printDocument, "document", false, "Pass 'true' to only print the document (unless other flags are provided as well).")
	return result
}

func deactivateCmd() *cobra.Command {
	result := &cobra.Command{
		Use:   "deactivate [DID]",
		Short: "Deactivate a DID document based on its DID",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !askYesNo("This will delete the DID document, are you sure?", cmd) {
				cmd.Println("Deactivation cancelled")
				return nil
			}
			clientConfig := core.NewClientConfigForCommand(cmd)
			err := httpClient(clientConfig).Deactivate(args[0])
			if err != nil {
				return fmt.Errorf("failed to deactivate DID document: %v", err)
			}
			cmd.Println("DID document deactivated")

			return nil
		},
	}
	return result
}

func addVerificationMethodCmd() *cobra.Command {
	result := &cobra.Command{
		Use:   "addvm [DID]",
		Short: "Add a verification method key to the DID document.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientConfig := core.NewClientConfigForCommand(cmd)
			verificationMethod, err := httpClient(clientConfig).AddNewVerificationMethod(args[0])
			if err != nil {
				return fmt.Errorf("failed to add a new verification method to DID document: %s", err.Error())
			}
			bytes, _ := json.MarshalIndent(verificationMethod, "", "  ")
			cmd.Printf("%s\n", string(bytes))
			return nil
		},
	}

	return result
}

func addKeyAgreementKeyCmd() *cobra.Command {
	result := &cobra.Command{
		Use:   "add-keyagreement [KID]",
		Short: "Add a key agreement key to the DID document.",
		Long: "Add a key agreement key to the DID document. " +
			"It must be a reference to an existing key in the same DID document, for instance created using the 'addvm' command. " +
			"When successful, it outputs the updated DID document.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			kid, err := did.ParseDIDURL(args[0])
			if err != nil {
				return fmt.Errorf("invalid key ID '%s': %w", args[0], err)
			}
			targetDID, _ := resolver.GetDIDFromURL(args[0]) // can't fail because we already parsed the key ID

			clientConfig := core.NewClientConfigForCommand(cmd)
			client := httpClient(clientConfig)
			document, metadata, err := client.Get(targetDID.String())
			if err != nil {
				return err
			}
			if metadata.Deactivated {
				return errors.New("DID document is deactivated")
			}

			var vm *did.VerificationMethod
			for _, curr := range document.VerificationMethod {
				if curr.ID.Equals(*kid) {
					vm = curr
					break
				}
			}

			if vm == nil {
				return errors.New("specified KID is not a verification method in the resolved DID document")
			}

			document.KeyAgreement.Add(vm)

			document, err = client.Update(targetDID.String(), metadata.Hash.String(), *document)
			if err != nil {
				return fmt.Errorf("error while updating the DID document: %w", err)
			}

			bytes, _ := json.MarshalIndent(document, "", "  ")
			cmd.Printf("%s\n", string(bytes))
			return nil
		},
	}

	return result
}

func deleteVerificationMethodCmd() *cobra.Command {
	result := &cobra.Command{
		Use:   "delvm [DID] [kid]",
		Short: "Deletes a verification method from the DID document.",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientConfig := core.NewClientConfigForCommand(cmd)
			err := httpClient(clientConfig).DeleteVerificationMethod(args[0], args[1])
			if err != nil {
				return fmt.Errorf("failed to delete the verification method from DID document: %s", err.Error())
			}
			cmd.Println("Verification method deleted from the DID document.")
			return nil
		},
	}

	return result
}

func askYesNo(question string, cmd *cobra.Command) (answer bool) {
	reader := bufio.NewReader(cmd.InOrStdin())
	question += "[yes/no]: "

	for {
		cmd.Print(question)
		s, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		s = strings.TrimSuffix(s, "\n")
		s = strings.ToLower(s)
		if s == "y" || s == "yes" {
			answer = true
			break
		} else if s == "n" || s == "no" {
			break
		}
		cmd.Println("invalid answer")
	}
	return
}

func readFromStdin() ([]byte, error) {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return nil, err
	}
	if fi.Mode()&os.ModeNamedPipe == 0 {
		return nil, errors.New("expected piped input")
	}
	return io.ReadAll(bufio.NewReader(os.Stdin))
}

// httpClient creates a remote client
func httpClient(config core.ClientConfig) api.HTTPClient {
	return api.HTTPClient{
		ClientConfig: config,
	}
}

// httpClientV2 creates a remote client using the V2 API
func httpClientV2(config core.ClientConfig) apiv2.HTTPClient {
	return apiv2.HTTPClient{
		ClientConfig: config,
	}
}
