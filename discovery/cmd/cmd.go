/*
 * Copyright (C) 2023 Nuts community
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
	flagSet.StringSlice("discovery.server.ids", defs.Server.IDs,
		"IDs of the Discovery Service for which to act as server. "+
			"If an ID does not map to a loaded service definition, the node will fail to start.")
	flagSet.Duration("discovery.client.refreshinterval", defs.Client.RefreshInterval,
		"Interval at which the client synchronizes with the Discovery Server; "+
			"refreshing Verifiable Presentations of local DIDs and loading changes, updating the local copy. "+
			"It only will actually refresh registrations of local DIDs that about to expire (less than 1/4th of their lifetime left). "+
			"Specified as Golang duration (e.g. 1m, 1h30m).")
	flagSet.Duration("discovery.client.refresh_interval", 0,
		"Deprecated, use refresh_interval.")
	return flagSet
}
