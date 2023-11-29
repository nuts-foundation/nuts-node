package cmd

import (
	"github.com/nuts-foundation/nuts-node/discovery"
	"github.com/spf13/pflag"
)

// FlagSet contains flags relevant for the module.
func FlagSet() *pflag.FlagSet {
	defs := discovery.DefaultConfig()
	flagSet := pflag.NewFlagSet("discovery", pflag.ContinueOnError)
	flagSet.String("discovery.definitions.directory", defs.Definitions.Directory,
		"Directory to load Discovery Service Definitions from. If not set, the discovery service will be disabled. "+
			"If the directory contains JSON files that can't be parsed as service definition, the node will fail to start.")
	flagSet.StringSlice("discovery.server.definition_ids", defs.Server.DefinitionIDs,
		"IDs of the Discovery Service Definitions for which to act as server. "+
			"If an ID does not map to a loaded service definition, the node will fail to start.")
	return flagSet
}
