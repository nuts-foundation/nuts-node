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
	"log"
	"sort"
	"strconv"
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
	flagSet.String("network.grpcaddr", defs.GrpcAddr, "Only used by did:nuts/gRPC. Local address for gRPC to listen on. "+
		"If empty the gRPC server won't be started and other nodes will not be able to connect to this node "+
		"(outbound connections can still be made).")
	flagSet.Int("network.connectiontimeout", defs.ConnectionTimeout, "Only used by did:nuts/gRPC. Timeout before an outbound connection attempt times out (in milliseconds).")
	flagSet.Duration("network.maxbackoff", defs.MaxBackoff, "Only used by did:nuts/gRPC. Maximum between outbound connections attempts to unresponsive nodes (in Golang duration format, e.g. '1h', '30m').")
	flagSet.StringSlice("network.bootstrapnodes", defs.BootstrapNodes, "Only used by did:nuts/gRPC. List of bootstrap nodes ('<host>:<port>') which the node initially connect to.")
	flagSet.Bool("network.enablediscovery", defs.EnableDiscovery, "Only used by did:nuts/gRPC. Whether to enable automatic connecting to other nodes.")
	flagSet.String("network.nodedid", defs.NodeDID, "Only used by did:nuts/gRPC. Specifies the DID of the party that operates this node. It is used to identify the node on the network. If the DID document does not exist of is deactivated, the node will not start.")
	flagSet.IntSlice("network.protocols", defs.Protocols, "Only used by did:nuts/gRPC. Specifies the list of network protocols to enable on the server. They are specified by version (1, 2). If not set, all protocols are enabled.")
	flagSet.Int("network.v2.gossipinterval", defs.ProtocolV2.GossipInterval, "Only used by did:nuts/gRPC. Interval (in milliseconds) that specifies how often the node should gossip its new hashes to other nodes.")
	flagSet.Int("network.v2.diagnosticsinterval", defs.ProtocolV2.DiagnosticsInterval, "Only used by did:nuts/gRPC. Interval (in milliseconds) that specifies how often the node should broadcast its diagnostic information to other nodes (specify 0 to disable).")

	// Hide flags for did:nuts/gRPC functionality
	flagSet.VisitAll(func(flag *pflag.Flag) {
		_ = flagSet.MarkHidden(flag.Name)
	})

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

// convertRange is a utility function for converting optional string args to *int
func convertRange(s string) *int {
	// Empty strings are converted to nil
	if s == "" {
		return nil
	}

	// Non-empty strings are converted (if possible) to int pointers
	if n, err := strconv.ParseUint(s, 10, 32); err == nil {
		// Upon successful integer parsing return a pointer to the value
		nInt := int(n)
		return &nInt
	}

	// Panic if parsing fails
	log.Panicf("cannot parse argument: %v", s)

	// Never reached...but needed for the compiler
	return nil
}

func listCommand() *cobra.Command {
	var sortFlag string
	var rangeStart string
	var rangeEnd string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "Lists the transactions on the network",
		RunE: func(cmd *cobra.Command, args []string) error {
			clientConfig := core.NewClientConfigForCommand(cmd)

			params := &v1.ListTransactionsParams{
				Start: convertRange(rangeStart),
				End:   convertRange(rangeEnd),
			}

			transactions, err := httpClient(clientConfig).ListTransactions(params)
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
	cmd.Flags().StringVar(&rangeStart, "start", "", "inclusive start of lamport clock range")
	cmd.Flags().StringVar(&rangeEnd, "end", "", "exclusive end of lamport clock range")

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
		ClientConfig: config,
	}
}
