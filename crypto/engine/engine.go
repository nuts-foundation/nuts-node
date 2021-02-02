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

package engine

import (
	"crypto"
	"encoding/json"
	"fmt"
	"time"

	"github.com/nuts-foundation/nuts-node/core"
	crypto2 "github.com/nuts-foundation/nuts-node/crypto"
	api "github.com/nuts-foundation/nuts-node/crypto/api/v1"
	"github.com/nuts-foundation/nuts-node/crypto/util"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// ConfigStorage is used as --crypto.storage config flag
const ConfigStorage string = "crypto.storage"

// ConfigFSPath is used as --crypto.fspath config flagclient.getStoragePath()
const ConfigFSPath string = "crypto.fspath"

// NewCryptoEngine the engine configuration for nuts-go.
func NewCryptoEngine() (*core.Engine, crypto2.KeyStore) {
	cb := crypto2.Instance()

	return &core.Engine{
		Cmd:          cmd(),
		Config:       &cb.Config,
		ConfigKey:    "crypto",
		Configurable: cb,
		FlagSet:      flagSet(),
		Name:         "Crypto",
		Routes: func(router core.EchoRouter) {
			api.RegisterHandlers(router, &api.Wrapper{C: cb})
		},
		Runnable: cb,
	}, cb
}

// FlagSet returns the configuration flags for crypto
func flagSet() *pflag.FlagSet {
	flags := pflag.NewFlagSet("crypto", pflag.ContinueOnError)

	defs := crypto2.DefaultCryptoConfig()
	flags.String(ConfigStorage, defs.Storage, fmt.Sprintf("Storage to use, 'fs' for file system, default: %s", defs.Storage))
	flags.String(ConfigFSPath, defs.Fspath, fmt.Sprintf("When file system is used as storage, this configures the path where key material and the truststore are persisted, default: %v", defs.Fspath))

	return flags
}

// Cmd gives the sub-commands made available through crypto:
// * generateKeyPair: generate a new keyPair for a given legalEntity
// * publicKey: retrieve the keyPair for a given legalEntity
func cmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "crypto",
		Short: "crypto commands",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "publicKey [kid] [valid_at]",
		Short: "views the publicKey for a given kid",
		Long: "views the publicKey for a given kid. It'll output a JWK encoded public key and a PEM encoded public key. " +
			"The valid_at argument is optional, when given it must be a RFC3339 compliant string. If not given, now() is used.",

		Args: cobra.RangeArgs(1, 2),
		Run: func(cmd *cobra.Command, args []string) {
			cc := newCryptoClient(cmd)
			kid := args[0]
			var validAt *string

			if len(args) == 2 {
				validAt = &args[1]
			}

			jwkKey, err := cc.GetPublicKey(kid, validAt)
			if err != nil {
				cmd.Printf("Error printing publicKey: %v", err)
				return
			}

			// printout in JWK
			if err != nil {
				cmd.Printf("Error printing publicKey: %v", err)
				return
			}
			asJSON, err := json.MarshalIndent(jwkKey, "", "  ")
			if err != nil {
				cmd.Printf("Error printing publicKey: %v\n", err)
				return
			}
			cmd.Println("Public key in JWK:")
			cmd.Println(string(asJSON))
			cmd.Println("")

			// printout in PEM
			var target interface{}
			err = jwkKey.Raw(&target)
			if err != nil {
				cmd.Printf("Error printing publicKey: %v\n", err)
				return
			}

			publicKeyAsPEM, err := util.PublicKeyToPem(target.(crypto.PublicKey))
			if err != nil {
				cmd.Printf("Error printing publicKey: %v\n", err)
				return
			}
			cmd.Println("Public key in PEM:")
			cmd.Println(publicKeyAsPEM)
		},
	})

	return cmd
}

// newCryptoClient creates a remote client
func newCryptoClient(cmd *cobra.Command) api.HTTPClient {
	cfg := core.NewNutsConfig()
	cfg.Load(cmd)

	return api.HTTPClient{
		ServerAddress: cfg.Address,
		Timeout:       10 * time.Second,
	}
}
