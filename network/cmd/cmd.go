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
	"sort"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/nuts-foundation/nuts-node/core"
	hash2 "github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network"
	v1 "github.com/nuts-foundation/nuts-node/network/api/v1"
	"github.com/nuts-foundation/nuts-node/network/dag"
)

// FlagSet contains flags relevant for the VDR instance
func FlagSet() *pflag.FlagSet {
	defs := network.DefaultConfig()
	flagSet := pflag.NewFlagSet("network", pflag.ContinueOnError)
	flagSet.String("network.grpcaddr", defs.GrpcAddr, "Local address for gRPC to listen on. "+
		"If empty the gRPC server won't be started and other nodes will not be able to connect to this node "+
		"(outbound connections can still be made).")
	flagSet.String("network.publicaddr", defs.PublicAddr, "Public address (of this node) other nodes can use to connect to it. If set, it is registered on the nodelist.")
	flagSet.StringSlice("network.bootstrapnodes", defs.BootstrapNodes, "Comma-separated list of bootstrap nodes (`<host>:<port>`) which the node initially connect to.")
	flagSet.Bool("network.enabletls", defs.EnableTLS, "Whether to enable TLS for incoming and outgoing gRPC connections. "+
		"If set to `true` (which is default) `certfile` and `certkeyfile` MUST be configured.")
	flagSet.String("network.certfile", defs.CertFile, "PEM file containing the server certificate for the gRPC server. "+
		"Required when `enableTLS` is `true`.")
	flagSet.String("network.certkeyfile", defs.CertKeyFile, "PEM file containing the private key of the server certificate. "+
		"Required when `network.enabletls` is `true`.")
	flagSet.String("network.truststorefile", defs.TrustStoreFile, "PEM file containing the trusted CA certificates for authenticating remote gRPC servers.")
	flagSet.Int("network.adverthashesinterval", defs.AdvertHashesInterval, "Interval (in milliseconds) that specifies how often the node should broadcast its last hashes to other nodes.")
	return flagSet
}

// Cmd contains sub-commands for the remote client
func Cmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "network",
		Short: "network commands",
	}
	cmd.AddCommand(listCommand())
	cmd.AddCommand(getCommand())
	cmd.AddCommand(payloadCommand())
	return cmd
}

func payloadCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "payload [ref]",
		Short: "Retrieves the payload of a transaction from the network",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			hash, err := hash2.ParseHex(args[0])
			if err != nil {
				return err
			}
			data, err := httpClient(core.NewClientConfig(cmd.Flags())).GetTransactionPayload(hash)
			if err != nil {
				return err
			}
			if data == nil {
				cmd.PrintErrf("Transaction or contents not found: %s", hash)
				return nil
			}
			println(string(data))
			return nil
		},
	}
}

func getCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "get [ref]",
		Short: "Gets a transaction from the network",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			hash, err := hash2.ParseHex(args[0])
			if err != nil {
				return err
			}
			transaction, err := httpClient(core.NewClientConfig(cmd.Flags())).GetTransaction(hash)
			if err != nil {
				return err
			}
			if transaction == nil {
				cmd.PrintErrf("Transaction not found: %s", hash)
				return nil
			}
			cmd.Printf("Transaction %s:\n  Type: %s\n  Timestamp: %s\n", transaction.Ref(), transaction.PayloadType(), transaction.SigningTime())
			return nil
		},
	}
}

const sortFlagTime = "time"
const sortFlagType = "type"

func listCommand() *cobra.Command {
	var sortFlag string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "Lists the transactions on the network",
		RunE: func(cmd *cobra.Command, args []string) error {
			transactions, err := httpClient(core.NewClientConfig(cmd.Flags())).ListTransactions()
			if err != nil {
				return err
			}
			const format = "%-65s %-40s %-20s\n"
			cmd.Printf(format, "Hashes", "Timestamp", "Type")
			sortTransactions(transactions, sortFlag)
			for _, transaction := range transactions {
				cmd.Printf(format, transaction.Ref(), transaction.SigningTime(), transaction.PayloadType())
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&sortFlag, "sort", sortFlagTime, "sort the results on either time or type")
	return cmd
}

// Sorts the transactions by provided flag or by time.
func sortTransactions(transactions []dag.Transaction, sortFlag string) {
	sort.Slice(transactions, func(i, j int) bool {
		if sortFlag == sortFlagType {
			return transactions[i].PayloadType() < transactions[j].PayloadType()
		} // default is sortFlagTime:
		return transactions[i].SigningTime().Before(transactions[j].SigningTime())
	})
}

// httpClient creates a remote client
func httpClient(config core.ClientConfig) v1.HTTPClient {
	return v1.HTTPClient{
		ServerAddress: config.GetAddress(),
		Timeout:       config.Timeout,
	}
}
