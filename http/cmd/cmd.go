/*
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
 *
 */

package cmd

import (
	"crypto"
	"fmt"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/nuts-foundation/nuts-node/audit"
	cryptoCmd "github.com/nuts-foundation/nuts-node/crypto/cmd"
	"github.com/nuts-foundation/nuts-node/http"
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"strconv"
	"time"
)

// FlagSet defines the set of flags that sets the engine configuration
func FlagSet() *pflag.FlagSet {
	flags := pflag.NewFlagSet("http", pflag.ContinueOnError)

	defs := http.DefaultConfig()
	flags.String("http.internal.address", defs.Internal.Address, "Address and port the server will be listening to for internal-facing endpoints.")
	flags.String("http.public.address", defs.Public.Address, "Address and port the server will be listening to for public-facing endpoints.")
	flags.String("http.internal.auth.type", string(defs.Internal.Auth.Type), fmt.Sprintf("Whether to enable authentication for /internal endpoints, specify '%s' for bearer token mode or '%s' for legacy bearer token mode.", http.BearerTokenAuthV2, http.BearerTokenAuth))
	flags.String("http.internal.auth.audience", defs.Internal.Auth.Audience, "Expected audience for JWT tokens (default: hostname)")
	flags.String("http.internal.auth.authorizedkeyspath", defs.Internal.Auth.AuthorizedKeysPath, "Path to an authorized_keys file for trusted JWT signers")
	flags.String("http.log", string(defs.Log), fmt.Sprintf("What to log about HTTP requests. Options are '%s', '%s' (log request method, URI, IP and response code), and '%s' (log the request and response body, in addition to the metadata).", http.LogNothingLevel, http.LogMetadataLevel, http.LogMetadataAndBodyLevel))

	return flags
}

// ServerCmd contains sub-commands for the HTTP engine
func ServerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "http",
		Short: "http commands",
	}
	cmd.AddCommand(createTokenCommand())
	return cmd
}

func createTokenCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "gen-token [user name] [days valid]",
		Short: "Generates an access token for administrative operations.",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := audit.Context(cmd.Context(), "app-cli", network.ModuleName, cmd.Name())

			daysValid, err := strconv.Atoi(args[1])
			if err != nil {
				return err
			}
			user := args[0]

			cmd.Println(fmt.Sprintf("Generating API token for user %s, valid for %d days...", user, daysValid))

			instance, err := cryptoCmd.LoadCryptoModule(cmd)
			if err != nil {
				return err
			}

			if !instance.Exists(cmd.Context(), http.AdminTokenSigningKID) {
				cmd.Println("Token signing key not found, generating new key...")
				_, err := instance.New(ctx, func(key crypto.PublicKey) (string, error) {
					return http.AdminTokenSigningKID, nil
				})
				if err != nil {
					return err
				}
			}
			token, err := instance.SignJWT(ctx, map[string]interface{}{
				jwt.SubjectKey:    user,
				jwt.ExpirationKey: time.Now().AddDate(0, 0, daysValid),
			}, nil, http.AdminTokenSigningKID)
			if err != nil {
				return err
			}
			cmd.Println()
			cmd.Println("Token:")
			cmd.Println()
			cmd.Println(token)
			cmd.Println()
			cmd.Println("You can provide it manually when executing CLI commands (using --token), " +
				"or save it in a file and use --token-file to have the CLI read it.")

			return nil
		},
	}
}
