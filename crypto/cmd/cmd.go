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
	"context"
	"errors"
	"fmt"
	"github.com/nuts-foundation/nuts-node/core"
	cryptoEngine "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/storage/azure"
	"github.com/nuts-foundation/nuts-node/crypto/storage/external"
	"github.com/nuts-foundation/nuts-node/crypto/storage/fs"
	"github.com/nuts-foundation/nuts-node/crypto/storage/spi"
	"github.com/nuts-foundation/nuts-node/crypto/storage/vault"
	storage2 "github.com/nuts-foundation/nuts-node/storage"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// FlagSet returns the configuration flags for crypto
func FlagSet() *pflag.FlagSet {
	flags := pflag.NewFlagSet("crypto", pflag.ContinueOnError)

	defs := cryptoEngine.DefaultCryptoConfig()
	flags.String("crypto.storage", defs.Storage, fmt.Sprintf("Storage to use, '%s' for file system (for development purposes), '%s' for HashiCorp Vault KV store, '%s' for Azure Key Vault, '%s' for an external backend (deprecated).",
		fs.StorageType, vault.StorageType, azure.StorageType, external.StorageType))
	flags.String("crypto.vault.token", defs.Vault.Token, "The Vault token. If set it overwrites the VAULT_TOKEN env var.")
	flags.String("crypto.vault.address", defs.Vault.Address, "The Vault address. If set it overwrites the VAULT_ADDR env var.")
	flags.Duration("crypto.vault.timeout", defs.Vault.Timeout, "Timeout of client calls to Vault, in Golang time.Duration string format (e.g. 1s).")
	flags.String("crypto.vault.pathprefix", defs.Vault.PathPrefix, "The Vault path prefix.")
	flags.String("crypto.azurekv.url", defs.AzureKeyVault.URL, "The URL of the Azure Key Vault.")
	flags.Duration("crypto.azurekv.timeout", defs.AzureKeyVault.Timeout, "Timeout of client calls to Azure Key Vault, in Golang time.Duration string format (e.g. 10s).")
	flags.Bool("crypto.azurekv.hsm", defs.AzureKeyVault.UseHSM, fmt.Sprintf("Whether to store the key in a hardware security module (HSM). If true, the Azure Key Vault must be configured for HSM usage. Default: %t", defs.AzureKeyVault.UseHSM))
	flags.String("crypto.azurekv.auth.type", defs.AzureKeyVault.Auth.Type, fmt.Sprintf("Credential type to use when authenticating to the Azure Key Vault. Options: %s, %s (see https://github.com/Azure/azure-sdk-for-go/blob/main/sdk/azidentity/README.md for an explanation of the options).", azure.DefaultChainCredentialType, azure.ManagedIdentityCredentialType))
	flags.String("crypto.external.address", defs.External.Address, "Address of the external storage service.")
	flags.Duration("crypto.external.timeout", defs.External.Timeout, "Time-out when invoking the external storage backend, in Golang time.Duration string format (e.g. 1s).")

	_ = flags.MarkDeprecated("crypto.external.address", "Use another key storage backend instead of the external storage backend.")
	_ = flags.MarkDeprecated("crypto.external.timeout", "Use another key storage backend instead of the external storage backend.")

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
			keys, err := fsToOtherStorage(cmd.Context(), directory, target)
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
	storage := storage2.New()
	instance := cryptoEngine.NewCryptoInstance(storage)
	err = cfg.InjectIntoEngine(instance)
	if err != nil {
		return nil, err
	}
	err = storage.Configure(*cfg)
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
func fsToOtherStorage(ctx context.Context, sourceDir string, target spi.Storage) ([]string, error) {
	source, err := fs.NewFileSystemBackend(sourceDir)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize filesystem storage: %w", err)
	}

	return exportToOtherStorage(ctx, source, target)
}

// exportToOtherStorage exports all private keys from the source storage to the target storage.
// It accepts a source, target and returns all exported keys.
// If an error occurs, the returned keys are the keys that were exported before the error occurred.
func exportToOtherStorage(ctx context.Context, source, target spi.Storage) ([]string, error) {
	var keys []string
	keyNames, versions := source.ListPrivateKeys(ctx)
	for i := range keyNames {
		keyName := keyNames[i]
		version := versions[i]
		privateKey, err := source.GetPrivateKey(ctx, keyName, version)
		if err != nil {
			return keys, fmt.Errorf("unable to retrieve private key (kid=%s): %w", keyName, err)
		}
		err = target.SavePrivateKey(ctx, keyName, privateKey)
		if err != nil {
			// ignore duplicate keys, allows for reruns
			if errors.Is(err, spi.ErrKeyAlreadyExists) {
				continue
			}
			return keys, fmt.Errorf("unable to store private key in Vault (kid=%s): %w", keyName, err)
		}
		// only add if no error occurred
		keys = append(keys, keyName)
	}
	return keys, nil
}
