package cmd

import (
	"github.com/nuts-foundation/nuts-node/auth"
	"github.com/spf13/pflag"
)

// ConfPublicURL is the config key for the public URL the http/irma server can be discovered
const ConfPublicURL = "auth.publicurl"

// ConfContractValidators is the config key for defining which contract validators to use
const ConfContractValidators = "auth.contractvalidators"

// ConfAutoUpdateIrmaSchemas is the config key to provide an option to skip auto updating the irma schemas
const ConfAutoUpdateIrmaSchemas = "auth.irma.autoupdateschemas"

// ConfIrmaSchemeManager allows selecting an IRMA scheme manager. During development this can ben irma-demo. Production should be pdfb
const ConfIrmaSchemeManager = "auth.irma.schemamanager"

// FlagSet returns the configuration flags supported by this module.
func FlagSet() *pflag.FlagSet {
	flags := pflag.NewFlagSet("auth", pflag.ContinueOnError)

	defs := auth.DefaultConfig()
	flags.String(ConfIrmaSchemeManager, defs.Irma.SchemeManager, "IRMA schemeManager to use for attributes. Can be either 'pbdf' or 'irma-demo'.")
	flags.String(ConfPublicURL, defs.PublicURL, "public URL which can be reached by a users IRMA client")
	flags.Bool(ConfAutoUpdateIrmaSchemas, defs.Irma.AutoUpdateSchemas, "set if you want automatically update the IRMA schemas every 60 minutes.")
	flags.StringSlice(ConfContractValidators, defs.ContractValidators, "sets the different contract validators to use")

	return flags
}
