package cmd

import (
	"context"
	"fmt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/core"
	cryptoEngine "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/nuts-foundation/nuts-node/vdr/doc"
	"github.com/nuts-foundation/nuts-node/vdr/store"
	"github.com/spf13/cobra"
	"sort"
)

func analyzeSigners(state dag.State) (map[string]int, error) {
	const newKeyID = "(unknown signer: embedded JWT)"
	result := make(map[string]int)
	err := state.Walk(context.Background(), func(transaction dag.Transaction) bool {
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
		return true
	}, hash.EmptyHash())
	return result, err
}

func analyzeCommand() *cobra.Command {
	result := &cobra.Command{
		Use: "analyze",
	}
	result.AddCommand(&cobra.Command{
		Use: "signers",
		Short: "Analyze the number of transactions per signer (DID). " +
			"It takes the server configuration to connect to the node database(s). " +
			"Note that some file-based databases don't support multiple connections, in that case node needs to be shut down to run this command.",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Load config
			cfg := core.NewServerConfig()
			err := cfg.Load(cmd.Flags())
			if err != nil {
				return err
			}

			// Initialize modules
			storageInstance := storage.New()
			storageInstance.
			didStore := store.NewStore(storageInstance.GetProvider(vdr.ModuleName))


			network.NewNetworkInstance(cfg, doc.KeyResolver{Store: didStore}, nil, nil,  doc.Resolver{Store: didStore}, doc.Finder{Store: didStore}, nil, storageInstance.GetProvider(network.ModuleName))
			instance := cryptoEngine.NewCryptoInstance()
			err = cfg.InjectIntoEngine(instance)
			if err != nil {
				return nil
			}
			err = instance.Configure(*cfg)
			if err != nil {
				return err
			}
			targetStorage := instance.Storage

			directory := args[0]
			sourceStorage, err := storage.NewFileSystemBackend(directory)
			if err != nil {
				return fmt.Errorf("unable to initialize filesystem storage: %w", err)
			}


			state, err := dag.NewState(args[0])
			if err != nil {
				return err
			}

			// Pretty ASCII art
			cmd.Println("===================================")
			cmd.Println("Analyzing network state database...")
			cmd.Println("===================================")
			cmd.Println("Number of TXs per signer:")
			txCountPerSigner, err := analyzeSigners(state)
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

