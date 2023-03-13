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
	"errors"
	"fmt"
	"github.com/nuts-foundation/nuts-node/core"
	cryptoEngine "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/storage/external"
	"github.com/nuts-foundation/nuts-node/crypto/storage/fs"
	"github.com/nuts-foundation/nuts-node/crypto/storage/spi"
	"github.com/nuts-foundation/nuts-node/crypto/storage/vault"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// FlagSet returns the configuration flags for crypto
func FlagSet() *pflag.FlagSet {
	flags := pflag.NewFlagSet("crypto", pflag.ContinueOnError)

	defs := cryptoEngine.DefaultCryptoConfig()
	flags.String("crypto.storage", defs.Storage, fmt.Sprintf("Storage to use, '%s' for an external backend (experimental), "+
		"'%s' for file system (for development purposes), "+
		"'%s' for Vault KV store (recommended, will be replaced by external backend in future).", external.StorageType, fs.StorageType, vault.StorageType))
	flags.String("crypto.vault.token", defs.Vault.Token, "The Vault token. If set it overwrites the VAULT_TOKEN env var.")
	flags.String("crypto.vault.address", defs.Vault.Address, "The Vault address. If set it overwrites the VAULT_ADDR env var.")
	flags.Duration("crypto.vault.timeout", defs.Vault.Timeout, "Timeout of client calls to Vault, in Golang time.Duration string format (e.g. 1s).")
	flags.String("crypto.vault.pathprefix", defs.Vault.PathPrefix, "The Vault path prefix.")
	flags.String("crypto.external.address", defs.External.Address, "Address of the external storage service.")
	flags.Duration("crypto.external.timeout", defs.External.Timeout, "Time-out when invoking the external storage backend, in Golang time.Duration string format (e.g. 1s).")

	return flags
}

// ServerCmd returns contains CLI commands for crypto that use the server configuration.
func ServerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "crypto",
		Short: "crypto commands",
	}
	cmd.AddCommand(fs2VaultCommand())
	cmd.AddCommand(fs2ExternalStore())
	return cmd
}

func fs2ExternalStore() *cobra.Command {
	return &cobra.Command{
		Use:   "fs2external [directory]",
		Short: "Imports private keys from filesystem based storage (located at the given directory) into the storage server.",
		Long: "Imports private keys from filesystem based storage into the secret store server. The given directory must contain the private key files. " +
			"The Nuts node must be configured to use storage-api as crypto storage. Can only be run on the local Nuts node, from the directory where nuts.yaml resides.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.Println("Exporting keys from FileSystem storage to the external storage service...")

			instance, err := LoadCryptoModule(cmd)
			if err != nil {
				return err
			}
			config := instance.Config().(*cryptoEngine.Config)
			targetStorage, err := external.NewAPIClient(config.External)
			if err != nil {
				return err
			}

			directory := args[0]
			keys, err := fsToOtherStorage(directory, targetStorage)
			cmd.Println(fmt.Sprintf("Imported %d keys:", len(keys)))
			for _, key := range keys {
				cmd.Println("  ", key)
			}
			if err != nil {
				cmd.Println("Failed to import all fs keys into external store:", err)
				return err
			}
			return nil
		},
	}
}

func fs2VaultCommand() *cobra.Command {
	return &cobra.Command{
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

			target, err := vault.NewVaultKVStorage(config.Vault)
			if err != nil {
				return err
			}

			directory := args[0]
			keys, err := fsToOtherStorage(directory, target)
			cmd.Println(fmt.Sprintf("Imported %d keys:", len(keys)))
			for _, key := range keys {
				cmd.Println("  ", key)
			}

			if err != nil {
				cmd.Println("Failed to import all fs keys into external Vault: ", err)
				return err
			}

			return nil
		},
	}
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

// fsToOtherStorage imports keys from the given directory into the given storage.
// It accepts a source directory and a target storage. It returns a list of keys that were imported and a possible error.
func fsToOtherStorage(sourceDir string, target spi.Storage) ([]string, error) {
	source, err := fs.NewFileSystemBackend(sourceDir)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize filesystem storage: %w", err)
	}

	return exportToOtherStorage(source, target)
}

// exportToOtherStorage exports all private keys from the source storage to the target storage.
// It accepts a source, target and returns all exported keys.
// If an error occurs, the returned keys are the keys that were exported before the error occurred.
func exportToOtherStorage(source, target spi.Storage) ([]string, error) {
	var keys []string
	for _, kid := range source.ListPrivateKeys() {
		privateKey, err := source.GetPrivateKey(kid)
		if err != nil {
			return keys, fmt.Errorf("unable to retrieve private key (kid=%s): %w", kid, err)
		}
		err = target.SavePrivateKey(kid, privateKey)
		if err != nil {
			// ignore duplicate keys, allows for reruns
			if errors.Is(err, spi.ErrKeyAlreadyExists) {
				continue
			}
			return keys, fmt.Errorf("unable to store private key in Vault (kid=%s): %w", kid, err)
		}
		// only add if no error occurred
		keys = append(keys, kid)
	}
	return keys, nil
}
