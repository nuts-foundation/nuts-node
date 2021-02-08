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

package vdr

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/core"
	api "github.com/nuts-foundation/nuts-node/vdr/api/v1"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func (r *VDR) FlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("vdr", pflag.ContinueOnError)

	defs := DefaultConfig()
	flagSet.Int(ConfClientTimeout, defs.ClientTimeout, fmt.Sprintf("Time-out for the client in seconds (e.g. when using the CLI), default: %d", defs.ClientTimeout))

	return flagSet
}

func (r *VDR) Cmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vdr",
		Short: "Verifiable Data VDR commands",
	}

	cmd.AddCommand(createCmd())

	cmd.AddCommand(resolveCmd())

	cmd.AddCommand(updateCmd())

	return cmd
}

func createCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "create-did",
		Short: "Registers a new DID",
		Args:  cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			client := httpClient(cmd)

			doc, err := client.Create()
			if err != nil {
				return fmt.Errorf("unable to create new DID: %v", err)
			}

			bytes, _ := json.MarshalIndent(doc, "", "  ")

			cmd.Printf("Created DID document: %s\n", string(bytes))
			return nil
		},
	}
}

func updateCmd() *cobra.Command {
	return &cobra.Command{
		Use: "update [DID] [hash] [file]",
		Short: "Update a DID with the given DID document, this replaces the DID document. " +
			"If no file is given, a pipe is assumed. The hash is needed to prevent concurrent updates.",
		Args: cobra.RangeArgs(2, 3),
		RunE: func(cmd *cobra.Command, args []string) error {
			client := httpClient(cmd)

			id := args[0]
			hash := args[1]

			var bytes []byte
			var err error
			if len(args) == 3 {
				// read from file
				bytes, err = ioutil.ReadFile(args[2])
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

			if _, err = client.Update(id, hash, didDoc); err != nil {
				return fmt.Errorf("failed to update DID document: %w", err)
			}

			cmd.Println("DID document updated")
			return nil
		},
	}
}

func resolveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "resolve [DID]",
		Short: "Resolve a DID document based on its DID",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client := httpClient(cmd)

			doc, meta, err := client.Get(args[0])
			if err != nil {
				return fmt.Errorf("failed to resolve DID document: %v", err)
			}

			for _, o := range []interface{}{doc, meta} {
				bytes, _ := json.MarshalIndent(o, "", "  ")
				cmd.Printf("%s\n", string(bytes))
			}

			return nil
		},
	}
}

func readFromStdin() ([]byte, error) {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return nil, err
	}
	if fi.Mode()&os.ModeNamedPipe == 0 {
		return nil, errors.New("expected piped input")
	}
	return ioutil.ReadAll(bufio.NewReader(os.Stdin))
}

func httpClient(cmd *cobra.Command) api.HTTPClient {
	cfg := core.NewNutsConfig()
	cfg.Load(cmd)

	// TODO: allow for https
	addr := cfg.Address
	if !strings.HasPrefix(addr, "http") {
		addr = "http://" + addr
	}
	return api.HTTPClient{
		ServerAddress: addr,
		Timeout:       5 * time.Second,
	}
}
