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
	"sort"
	"strings"

	"github.com/nuts-foundation/nuts-node/network"
	"github.com/nuts-foundation/nuts-node/network/transport"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/nuts-foundation/nuts-node/core"
	hash2 "github.com/nuts-foundation/nuts-node/crypto/hash"
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
	flagSet.Int("network.connectiontimeout", defs.ConnectionTimeout, "Timeout before an outbound connection attempt times out (in milliseconds).")
	flagSet.StringSlice("network.bootstrapnodes", defs.BootstrapNodes, "List of bootstrap nodes (`<host>:<port>`) which the node initially connect to.")
	flagSet.Bool("network.enablediscovery", defs.EnableDiscovery, "Whether to enable automatic connecting to other nodes.")
	flagSet.Bool("network.enabletls", defs.EnableTLS, "Whether to enable TLS for incoming and outgoing gRPC connections. "+
		"When `certfile` or `certkeyfile` is specified it defaults to `true`, otherwise `false`.")
	flagSet.String("network.certfile", defs.CertFile, "PEM file containing the server certificate for the gRPC server. "+
		"Required when `enableTLS` is `true`.")
	flagSet.String("network.certkeyfile", defs.CertKeyFile, "PEM file containing the private key of the server certificate. "+
		"Required when `network.enabletls` is `true`.")
	flagSet.String("network.truststorefile", defs.TrustStoreFile, "PEM file containing the trusted CA certificates for authenticating remote gRPC servers.")
	flagSet.Bool("network.disablenodeauthentication", defs.DisableNodeAuthentication, "Disable node DID authentication using client certificate, causing all node DIDs to be accepted. Unsafe option, only intended for workshops/demo purposes. Not allowed in strict-mode.")
	flagSet.String("network.nodedid", defs.NodeDID, "Specifies the DID of the organization that operates this node, typically a vendor for EPD software. It is used to identify the node on the network. If the DID document does not exist of is deactivated, the node will not start.")
	flagSet.IntSlice("network.protocols", defs.Protocols, "Specifies the list of network protocols to enable on the server. They are specified by version (1, 2). If not set, all protocols are enabled.")
	flagSet.Int("network.v2.gossipinterval", defs.ProtocolV2.GossipInterval, "Interval (in milliseconds) that specifies how often the node should gossip its new hashes to other nodes.")
	flagSet.Int("network.v2.diagnosticsinterval", defs.ProtocolV2.DiagnosticsInterval, "Interval (in milliseconds) that specifies how often the node should broadcast its diagnostic information to other nodes (specify 0 to disable).")
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
	cmd.AddCommand(peersCommand())
	cmd.AddCommand(reprocessCommand())
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
			clientConfig := core.NewClientConfigForCommand(cmd)
			if err != nil {
				return err
			}
			data, err := httpClient(clientConfig).GetTransactionPayload(hash)
			if err != nil {
				return fmt.Errorf("unable to get transaction payload: %w", err)
			}
			if data == nil {
				cmd.PrintErrf("Transaction or contents not found: %s", hash)
				return nil
			}
			cmd.Print(string(data))
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
			clientConfig := core.NewClientConfigForCommand(cmd)
			if err != nil {
				return err
			}
			transaction, err := httpClient(clientConfig).GetTransaction(hash)
			if err != nil {
				return fmt.Errorf("unable to get transaction: %w", err)
			}
			if transaction == nil {
				cmd.PrintErrf("Transaction not found: %s", hash)
				return nil
			}
			var prevs []string
			for _, prev := range transaction.Previous() {
				prevs = append(prevs, prev.String())
			}
			cmd.Printf("Transaction %s:\n  Type: %s\n  Timestamp: %s\n  Prevs: %s\n", transaction.Ref(), transaction.PayloadType(), transaction.SigningTime(), strings.Join(prevs, " "))
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
			clientConfig := core.NewClientConfigForCommand(cmd)
			transactions, err := httpClient(clientConfig).ListTransactions()
			if err != nil {
				return fmt.Errorf("unable to list transactions: %w", err)
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

func peersCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "peers",
		Short: "Get diagnostic information of the node's peers",
		RunE: func(cmd *cobra.Command, args []string) error {
			clientConfig := core.NewClientConfigForCommand(cmd)
			peers, err := httpClient(clientConfig).GetPeerDiagnostics()
			if err != nil {
				return fmt.Errorf("unable to get peer diagnostics: %w", err)
			}

			sortedPeers := make([]string, 0, len(peers))
			for peerID := range peers {
				sortedPeers = append(sortedPeers, peerID.String())
			}
			sort.Strings(sortedPeers)

			cmd.Printf("Listing %d peers:\n", len(peers))
			for _, curr := range sortedPeers {
				peer := transport.PeerID(curr)
				cmd.Printf("\n%s\n", peer)
				cmd.Printf("  SoftwareID:        %s\n", peers[peer].SoftwareID)
				cmd.Printf("  SoftwareVersion:   %s\n", peers[peer].SoftwareVersion)
				cmd.Printf("  Uptime:            %s\n", peers[peer].Uptime)
				cmd.Printf("  Number of DAG TXs: %d\n", peers[peer].NumberOfTransactions)
				cmd.Printf("  Peers:             %v\n", peers[peer].Peers)
			}
			return nil
		},
	}
}

func reprocessCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "reprocess [contentType]",
		Short: "Reprocess all transactions with the give contentType (ex: application/did+json)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			clientConfig := core.NewClientConfigForCommand(cmd)
			if err := httpClient(clientConfig).Reprocess(args[0]); err != nil {
				// prints help on 400
				return fmt.Errorf("unable to reprocess transactions: %w", err)
			}
			cmd.Printf("Reprocessing transactions with contentType: %s\n", args[0])
			return nil
		},
	}
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
