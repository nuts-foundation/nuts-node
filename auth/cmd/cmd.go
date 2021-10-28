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

// ConfNetworkTrustStoreFile defines a file to use as a TLS truststore
const ConfNetworkTrustStoreFile = "network.truststorefile"

// FlagSet returns the configuration flags supported by this module.
func FlagSet() *pflag.FlagSet {
	flags := pflag.NewFlagSet("auth", pflag.ContinueOnError)

	defs := auth.DefaultConfig()
	flags.String(ConfIrmaSchemeManager, defs.IrmaSchemeManager, "IRMA schemeManager to use for attributes. Can be either 'pbdf' or 'irma-demo'.")
	flags.String(ConfPublicURL, defs.PublicURL, "public URL which can be reached by a users IRMA client, this should include the scheme and domain: https://example.com. Additional paths should only be added if some sort of url-rewriting is done in a reverse-proxy.")
	flags.Bool(ConfAutoUpdateIrmaSchemas, defs.IrmaAutoUpdateSchemas, "set if you want automatically update the IRMA schemas every 60 minutes.")
	flags.Int(ConfHTTPTimeout, defs.HTTPTimeout, "HTTP timeout (in seconds) used by the Auth API HTTP client")
	flags.Int(ConfClockSkew, defs.ClockSkew, "Allowed JWT Clock skew in milliseconds")
	flags.StringSlice(ConfContractValidators, defs.ContractValidators, "sets the different contract validators to use")
	flags.String(ConfNetworkTrustStoreFile, defs.TrustStoreFile, "PEM file containing the trusted CA certificates for authenticating remote gRPC servers.")

	return flags
}
