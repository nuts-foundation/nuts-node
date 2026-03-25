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
	"github.com/nuts-foundation/nuts-node/auth"
	"github.com/spf13/pflag"
)

// ConfClockSkew is the config key for allowed JWT clockskew (deviance of iat, exp) in milliseconds
const ConfClockSkew = "auth.clockskew"

// ConfContractValidators is the config key for defining which contract validators to use
const ConfContractValidators = "auth.contractvalidators"

// ConfAutoUpdateIrmaSchemas is the config key to provide an option to skip auto updating the irma schemas
const ConfAutoUpdateIrmaSchemas = "auth.irma.autoupdateschemas"

// ConfIrmaSchemeManager allows selecting an IRMA scheme manager. During development this can ben irma-demo. Production should be pdfb
const ConfIrmaSchemeManager = "auth.irma.schememanager"

// ConfIrmaCorsOrigin is the config key for the allowed CORS origins for the IRMA server
const ConfIrmaCorsOrigin = "auth.irma.cors.origin"

// ConfHTTPTimeout defines a timeout (in seconds) which is used by the Auth API HTTP client
const ConfHTTPTimeout = "auth.http.timeout"

// ConfAccessTokenLifeSpan defines how long (in seconds) an access token is valid
const ConfAccessTokenLifeSpan = "auth.accesstokenlifespan"

// ConfAuthEndpointEnabled is the config key for enabling the Auth v2 API's Authorization Endpoint
// Deprecated: use ConfOpenID4VPEnabled and ConfOpenID4VCIEnabled instead.
const ConfAuthEndpointEnabled = "auth.authorizationendpoint.enabled"

// ConfOpenID4VPEnabled is the config key for enabling OpenID4VP
const ConfOpenID4VPEnabled = "auth.openid4vp.enabled"

// ConfOpenID4VCIEnabled is the config key for enabling OpenID4VCI (client)
const ConfOpenID4VCIEnabled = "auth.openid4vci.enabled"

// FlagSet returns the configuration flags supported by this module.
func FlagSet() *pflag.FlagSet {
	flags := pflag.NewFlagSet("auth", pflag.ContinueOnError)

	defs := auth.DefaultConfig()
	flags.String(ConfIrmaSchemeManager, defs.Irma.SchemeManager, "IRMA schemeManager to use for attributes. Can be either 'pbdf' or 'irma-demo'.")
	flags.Bool(ConfAutoUpdateIrmaSchemas, defs.Irma.AutoUpdateSchemas, "set if you want automatically update the IRMA schemas every 60 minutes.")
	flags.StringSlice(ConfIrmaCorsOrigin, defs.Irma.CORS.Origin, "sets the allowed CORS origins for the IRMA server")
	flags.Int(ConfHTTPTimeout, defs.HTTPTimeout, "HTTP timeout (in seconds) used by the Auth API HTTP client")
	flags.Int(ConfClockSkew, defs.ClockSkew, "allowed JWT Clock skew in milliseconds")
	flags.Int(ConfAccessTokenLifeSpan, defs.AccessTokenLifeSpan, "defines how long (in seconds) an access token is valid. Uses default in strict mode.")
	flags.StringSlice(ConfContractValidators, defs.ContractValidators, "sets the different contract validators to use")
	flags.Bool(ConfAuthEndpointEnabled, defs.AuthorizationEndpoint.Enabled, "enables the v2 API's OAuth2 Authorization Endpoint, used by OpenID4VP and OpenID4VCI. "+
		"Deprecated: use auth.openid4vp.enabled and auth.openid4vci.enabled instead.")
	flags.Bool(ConfOpenID4VPEnabled, defs.OpenID4VP.Enabled, "enables OpenID4VP, allowing the node to act as an OpenID4VP verifier and wallet.")
	flags.Bool(ConfOpenID4VCIEnabled, defs.OpenID4VCI.Enabled, "enables OpenID4VCI (client), allowing the node to act as an OpenID4VCI wallet.")
	_ = flags.MarkDeprecated(ConfAuthEndpointEnabled, "use auth.openid4vp.enabled and auth.openid4vci.enabled instead")
	_ = flags.MarkDeprecated("auth.http.timeout", "use httpclient.timeout instead")

	return flags
}
