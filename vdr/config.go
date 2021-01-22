package vdr

// ConfDataDir is the config name for specifiying the data location of the requiredFiles
const ConfDataDir = "datadir"

// ConfMode is the config name for the engine mode, server or client
const ConfMode = "mode"

// ConfAddress is the config name for the http server/client address
const ConfAddress = "address"

// ConfClientTimeout is the time-out for the client in seconds (e.g. when using the CLI).
const ConfClientTimeout = "clientTimeout"

// ModuleName == Verifiable Data Registry
const ModuleName = "Verifiable Data Registry"

// Config holds the config for the Registry engine
type Config struct {
	Datadir       string
	ClientTimeout int
}

// DefaultRegistryConfig returns a fresh Config filled with default values
func DefaultRegistryConfig() Config {
	return Config{
		Datadir:       "./data",
		ClientTimeout: 10,
	}
}
