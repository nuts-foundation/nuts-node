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
	"github.com/nuts-foundation/nuts-node/core"
	cryptoEngine "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/storage"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// FlagSet returns the configuration flags for crypto
func FlagSet() *pflag.FlagSet {
	flags := pflag.NewFlagSet("crypto", pflag.ContinueOnError)

	defs := cryptoEngine.DefaultCryptoConfig()
	flags.String("crypto.storage", defs.Storage, "Storage to use, 'fs' for file system, 'vaultkv' for Vault KV store.")
	flags.String("crypto.vault.token", defs.Vault.Token, "The Vault token. If set it overwrites the VAULT_TOKEN env var.")
	flags.String("crypto.vault.address", defs.Vault.Address, "The Vault address. If set it overwrites the VAULT_ADDR env var.")
	flags.Duration("crypto.vault.timeout", defs.Vault.Timeout, "Timeout of client calls to Vault, in Golang time.Duration string format (e.g. 5s).")
	flags.String("crypto.vault.pathprefix", defs.Vault.PathPrefix, "The Vault path prefix.")

	return flags
}

// ServerCmd returns contains CLI commands for crypto that use the server configuration.
func ServerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "crypto",
		Short: "crypto commands",
	}
	cmd.AddCommand(fs2VaultCommand())
	return cmd
}

func fs2VaultCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fs2vault [directory]",
		Short: "Imports private keys from filesystem based storage (located at the given directory) into Vault.",
		Long: "Imports private keys from filesystem based storage into Vault. The given directory must contain the private key files." +
			"The Nuts node must be configured to use Vault as crypto storage. Can only be run on the local Nuts node, from the directory where nuts.yaml resides.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.Println("Importing keys on FileSystem storage into Vault...")

			instance, err := LoadCryptoModule(cmd)
			if err != nil {
				return err
			}
			config := instance.Config().(*cryptoEngine.Config)
			targetStorage, err := storage.NewVaultKVStorage(config.Vault)
			if err != nil {
				return err
			}

			directory := args[0]
			sourceStorage, err := storage.NewFileSystemBackend(directory)
			if err != nil {
				return fmt.Errorf("unable to initialize filesystem storage: %w", err)
			}

			for _, kid := range sourceStorage.ListPrivateKeys() {
				privateKey, err := sourceStorage.GetPrivateKey(kid)
				if err != nil {
					return fmt.Errorf("unable to retrieve private key (kid=%s): %w", kid, err)
				}
				err = targetStorage.SavePrivateKey(kid, privateKey)
				if err != nil {
					return fmt.Errorf("unable to store private key in Vault (kid=%s): %w", kid, err)
				}
				cmd.Println("  Imported:", kid)
			}
			cmd.Println("Done!")
			return nil
		},
	}
	return cmd
}

// LoadCryptoModule creates a Crypto module instance and configures it using the given server root command.
func LoadCryptoModule(cmd *cobra.Command) (*cryptoEngine.Crypto, error) {
	cfg := core.NewServerConfig()
	err := cfg.Load(cmd.Flags())
	if err != nil {
		return nil, err
	}
	instance := cryptoEngine.NewCryptoInstance()
	err = cfg.InjectIntoEngine(instance)
	if err != nil {
		return nil, err
	}
	err = instance.Configure(*cfg)
	if err != nil {
		return nil, err
	}
	return instance, nil
}
