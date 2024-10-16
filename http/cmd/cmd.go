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
	"fmt"
	"github.com/nuts-foundation/nuts-node/http"
	"github.com/spf13/pflag"
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
	flags.String("http.log", string(defs.Log), fmt.Sprintf("What to log about HTTP requests. Options are '%s', '%s' (log request method, URI, IP and response code), and '%s' (log the request and response body, in addition to the metadata). When debug vebosity is set the authorization headers are also logged when the request is fully logged.", http.LogNothingLevel, http.LogMetadataLevel, http.LogMetadataAndBodyLevel))
	flags.String("http.clientipheader", defs.ClientIPHeaderName, "Case-sensitive HTTP Header that contains the client IP used for audit logs. For the X-Forwarded-For header only link-local, loopback, and private IPs are excluded. Switch to X-Real-IP or a custom header if you see your own proxy/infra in the logs.")
	flags.Int("http.cache.maxbytes", defs.ResponseCacheSize, "HTTP client maximum size of the response cache in bytes. If 0, the HTTP client does not cache responses.")

	return flags
}
