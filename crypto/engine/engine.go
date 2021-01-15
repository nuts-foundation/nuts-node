/*
 * Nuts crypto
 * Copyright (C) 2019. Nuts community
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
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/nuts-foundation/nuts-node/core"
	crypto2 "github.com/nuts-foundation/nuts-node/crypto"
	api "github.com/nuts-foundation/nuts-node/crypto/api/v1"
	"github.com/nuts-foundation/nuts-node/crypto/types"
	"github.com/nuts-foundation/nuts-node/crypto/util"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// NewCryptoEngine the engine configuration for nuts-go.
func NewCryptoEngine() *core.Engine {
	cb := crypto2.Instance()

	return &core.Engine{
		Cmd:       cmd(),
		Config:    &cb.Config,
		ConfigKey: "crypto",
		Configure: cb.Configure,
		FlagSet:   flagSet(),
		Name:      "Crypto",
		Routes: func(router core.EchoRouter) {
			api.RegisterHandlers(router, &api.Wrapper{C: cb})
		},
		Shutdown: cb.Shutdown,
	}
}

// FlagSet returns the configuration flags for crypto
func flagSet() *pflag.FlagSet {
	flags := pflag.NewFlagSet("crypto", pflag.ContinueOnError)

	defs := crypto2.DefaultCryptoConfig()
	flags.String(types.ConfigStorage, defs.Storage, fmt.Sprintf("Storage to use, 'fs' for file system, default: %s", defs.Storage))
	flags.String(types.ConfigFSPath, defs.Fspath, fmt.Sprintf("When file system is used as storage, this configures the path where key material and the truststore are persisted, default: %v", defs.Fspath))

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
		Use:   "server",
		Short: "Run standalone crypto server",
		Run: func(cmd *cobra.Command, args []string) {
			cryptoEngine := crypto2.Instance()
			echoServer := echo.New()
			echoServer.HideBanner = true
			echoServer.Use(middleware.Logger())
			api.RegisterHandlers(echoServer, &api.Wrapper{C: cryptoEngine})
			logrus.Fatal(echoServer.Start(":1324"))
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "publicKey [kid]",
		Short: "views the publicKey for a given kid",
		Long:  "views the publicKey for a given kid. It'll output a JWK encoded public key and a PEM encoded public key.",

		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return errors.New("requires a kid argument")
			}

			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			cc := newCryptoClient(cmd)
			kid := args[0]

			pubKey, err := cc.GetPublicKey(kid)
			if err != nil {
				cmd.Printf("Error printing publicKey: %v", err)
				return
			}

			// printout in JWK
			jwk, err := jwk.New(pubKey)
			if err != nil {
				cmd.Printf("Error printing publicKey: %v", err)
				return
			}
			asJSON, err := json.MarshalIndent(jwk, "", "  ")
			if err != nil {
				cmd.Printf("Error printing publicKey: %v\n", err)
				return
			}
			cmd.Println("Public key in JWK:")
			cmd.Println(string(asJSON))
			cmd.Println("")

			// printout in PEM
			publicKeyAsPEM, err := util.PublicKeyToPem(pubKey)
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
func newCryptoClient(cmd *cobra.Command) api.HttpClient {
	cfg := core.NutsConfig()
	cfg.Load(cmd)

	return api.HttpClient{
		ServerAddress: cfg.ServerAddress(),
		Timeout:       10 * time.Second,
	}
}
