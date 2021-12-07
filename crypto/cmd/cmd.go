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

	crypto2 "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/spf13/pflag"
)

// ConfigStorage is used as --crypto.storage config flag
const ConfigStorage string = "crypto.storage"
const ConfigVaultToken string = "crypto.vaultToken"
const ConfigVaultAddr string = "crypto.vaultAddr"

// FlagSet returns the configuration flags for crypto
func FlagSet() *pflag.FlagSet {
	flags := pflag.NewFlagSet("crypto", pflag.ContinueOnError)

	defs := crypto2.DefaultCryptoConfig()
	flags.String(ConfigStorage, defs.Storage, fmt.Sprintf("Storage to use, 'fs' for file system, vaultkv for Vault KV store, default: %s.", defs.Storage))
	flags.String(ConfigVaultToken, defs.VaultToken, "The Vault token. If set it overwrites the VAULT_TOKEN env var.")
	flags.String(ConfigVaultAddr, defs.VaultAddr, "The Vault address. If set it overwrites the VAULT_ADDR env var.")

	return flags
}
