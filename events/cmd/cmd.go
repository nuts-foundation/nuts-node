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
	"github.com/spf13/pflag"

	"github.com/nuts-foundation/nuts-node/events"
)

// ConfEventsPort defines the port for the NATS server
const ConfEventsPort = "events.nats.port"

// ConfEventsHostname defines the hostname for the NATS server
const ConfEventsHostname = "events.nats.hostname"

// ConfEventsStorageDir defines the storage directory for file-backed streams in the NATS server
const ConfEventsStorageDir = "events.nats.storagedir"

// ConfEventsTimeout defines the timeouts (in seconds) for the NATS server
const ConfEventsTimeout = "events.nats.timeout"

// FlagSet defines the set of flags that sets the events-engine configuration
func FlagSet() *pflag.FlagSet {
	flags := pflag.NewFlagSet("events", pflag.ContinueOnError)

	defs := events.DefaultConfig()
	flags.Int(ConfEventsPort, defs.Nats.Port, "Only used by did:nuts/gRPC. Port where the NATS server listens on")
	flags.String(ConfEventsHostname, defs.Nats.Hostname, "Only used by did:nuts/gRPC. Hostname for the NATS server")
	flags.String(ConfEventsStorageDir, defs.Nats.StorageDir, "Only used by did:nuts/gRPC. Directory where file-backed streams are stored in the NATS server")
	flags.Int(ConfEventsTimeout, defs.Nats.Timeout, "Only used by did:nuts/gRPC. Timeout for NATS server operations")
	return flags
}
