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

// ConfPublicURL is the config key for the public URL the http/irma server can be discovered
const ConfPublicURL = "auth.publicurl"

// ConfClockSkew is the config key for allowed JWT clockskew (deviance of iat, exp) in milliseconds
const ConfClockSkew = "auth.clockskew"

// ConfContractValidators is the config key for defining which contract validators to use
const ConfContractValidators = "auth.contractvalidators"

// ConfAutoUpdateIrmaSchemas is the config key to provide an option to skip auto updating the irma schemas
const ConfAutoUpdateIrmaSchemas = "auth.irma.autoupdateschemas"

// ConfIrmaSchemeManager allows selecting an IRMA scheme manager. During development this can ben irma-demo. Production should be pdfb
const ConfIrmaSchemeManager = "auth.irma.schememanager"

// ConfHTTPTimeout defines a timeout (in seconds) which is used by the Auth API HTTP client
const ConfHTTPTimeout = "auth.http.timeout"

// ConfAccessTokenLifeSpan defines how long (in seconds) an access token is valid
const ConfAccessTokenLifeSpan = "auth.accesstokenlifespan"

// ConfV2APIEnabled enables experimental v2 API endpoints
const ConfV2APIEnabled = "auth.v2apienabled"

const ConfPresentationExchangeMappingFile = "auth.presentationexchangemappingfile"

// FlagSet returns the configuration flags supported by this module.
func FlagSet() *pflag.FlagSet {
	flags := pflag.NewFlagSet("auth", pflag.ContinueOnError)

	defs := auth.DefaultConfig()
	flags.String(ConfIrmaSchemeManager, defs.Irma.SchemeManager, "IRMA schemeManager to use for attributes. Can be either 'pbdf' or 'irma-demo'.")
	flags.String(ConfPublicURL, defs.PublicURL, "public URL which can be reached by a users IRMA client, this should include the scheme and domain: https://example.com. Additional paths should only be added if some sort of url-rewriting is done in a reverse-proxy.")
	flags.Bool(ConfAutoUpdateIrmaSchemas, defs.Irma.AutoUpdateSchemas, "set if you want automatically update the IRMA schemas every 60 minutes.")
	flags.Int(ConfHTTPTimeout, defs.HTTPTimeout, "HTTP timeout (in seconds) used by the Auth API HTTP client")
	flags.Int(ConfClockSkew, defs.ClockSkew, "allowed JWT Clock skew in milliseconds")
	flags.Int(ConfAccessTokenLifeSpan, defs.AccessTokenLifeSpan, "defines how long (in seconds) an access token is valid. Uses default in strict mode.")
	flags.StringSlice(ConfContractValidators, defs.ContractValidators, "sets the different contract validators to use")
	flags.Bool(ConfV2APIEnabled, defs.V2APIEnabled, "enables experimental v2 API endpoints")
	flags.String(ConfPresentationExchangeMappingFile, defs.PresentationExchangeMappingFile, "sets the path to the presentation exchange mapping file")
	_ = flags.MarkHidden(ConfV2APIEnabled)

	return flags
}
