package jsonld

import (
	"github.com/spf13/pflag"
)

// FlagSet contains flags relevant for VCR
func FlagSet() *pflag.FlagSet {
	defs := DefaultConfig()
	flagSet := pflag.NewFlagSet("jsonld", pflag.ContinueOnError)
	flagSet.StringSlice("jsonld.contexts.remoteallowlist", defs.Contexts.RemoteAllowList, "In strict mode, fetching external JSON-LD contexts is not allowed except for context-URLs listed here.")
	flagSet.StringToString("jsonld.contexts.localmapping", defs.Contexts.LocalFileMapping, "This setting allows mapping external URLs to local files for e.g. preventing external dependencies. These mappings have precedence over those in remoteallowlist.")
	return flagSet
}
