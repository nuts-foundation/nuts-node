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

// FlagSet defines the set of flags that sets the events engine configuration
func FlagSet() *pflag.FlagSet {
	flags := pflag.NewFlagSet("events", pflag.ContinueOnError)

	defs := events.DefaultConfig()
	flags.Int(ConfEventsPort, defs.Port, "Port where the NATS server listens on")
	flags.String(ConfEventsHostname, defs.Hostname, "Hostname for the NATS server")
	flags.String(ConfEventsStorageDir, defs.StorageDir, "Directory where file-backed streams are stored in the NATS server")

	return flags
}
