package cmd

import (
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/nuts-foundation/nuts-node/vdr/doc"
	"github.com/nuts-foundation/nuts-node/vdr/store"
	"github.com/spf13/cobra"
	"math"
	"sort"
)

// ServerCmds returns contains CLI commands that use the server configuration.
func ServerCmds() *cobra.Command {
	cmd := &cobra.Command{
		Use: "analyze",
	}
	cmd.AddCommand(analyzeSignersCommand())
	return cmd
}

func analyzeSignersCommand() *cobra.Command {
	return &cobra.Command{
		Use: "signers",
		Short: "Analyze the number of transactions per signer (DID). " +
			"It takes the server configuration to connect to the node database(s). " +
			"Note that some file-based databases don't support multiple connections, in that case node needs to be shut down to run this command.",
		RunE: func(cmd *cobra.Command, args []string) error {
			system := core.NewSystem()
			networkInstance, err := registerModule(system)
			if err != nil {
				return err
			}
			err = system.Configure()
			if err != nil {
				return err
			}
			err = system.Start()
			if err != nil {
				return err
			}
			defer system.Shutdown()

			// Pretty ASCII art
			cmd.Println("===================================")
			cmd.Println("Analyzing network state database...")
			cmd.Println("===================================")
			cmd.Println("Number of TXs per signer:")
			txCountPerSigner, err := analyzeSigners(networkInstance)
			if err != nil {
				return err
			}
			// Invert map, sort by tx count and print
			signersPerTxCount := make(map[int][]string)
			var sortedCount []int
			for signer, count := range txCountPerSigner {
				if len(signersPerTxCount[count]) == 0 {
					sortedCount = append(sortedCount, count)
				}
				signersPerTxCount[count] = append(signersPerTxCount[count], signer)
			}
			sort.Ints(sortedCount)
			// Show signers with TX count descending order (signers with most TXs first)
			for i := len(sortedCount) - 1; i >= 0; i-- {
				txCount := sortedCount[i]
				for _, signer := range signersPerTxCount[txCount] {
					cmd.Println(signer, ":", txCount)
				}
			}

			cmd.Println("===================================")
			cmd.Println("Done!")
			cmd.Println("===================================")
			return nil
		},
	}
}

func analyzeSigners(net *network.Network) (map[string]int, error) {
	const newKeyID = "(unknown signer: embedded JWT)"
	const chunk = 1000
	result := make(map[string]int)

	for i := uint32(0); i < math.MaxUint32; i += chunk {
		txs, err := net.ListTransactionsInRange(i, i+chunk)
		if err != nil {
			return nil, err
		}
		if len(txs) == 0 {
			// Reached end of DAG
			return result, nil
		}

		for _, transaction := range txs {
			var signerID string
			if transaction.SigningKeyID() == "" {
				signerID = newKeyID
			} else {
				kid, err := did.ParseDIDURL(transaction.SigningKeyID())
				if err != nil {
					println("Invalid key ID:", err.Error())
					signerID = transaction.SigningKeyID()
				} else {
					kid.Fragment = ""
					kid.Query = ""
					signerID = kid.String()
				}
			}
			result[signerID] = result[signerID] + 1
		}
	}

	return result, nil
}

func registerModule(system *core.System) (*network.Network, error) {
	// Initialize modules
	storageInstance := storage.New()
	didStore := store.NewStore(storageInstance.GetProvider(vdr.ModuleName))
	networkInstance := network.NewNetworkInstance(network.DefaultConfig(), doc.KeyResolver{Store: didStore}, nil, nil, doc.Resolver{Store: didStore}, doc.Finder{Store: didStore}, nil, storageInstance.GetProvider(network.ModuleName))

	system.RegisterEngine(storageInstance)
	system.RegisterEngine(networkInstance)

	return networkInstance, nil
}
