package vdr

const (
	moduleName = "Verifiable Data Registry"
	configKey  = "vdr"
)

// Config holds the config for the VDR engine
type Config struct{}

// DefaultConfig returns a fresh Config filled with default values
func DefaultConfig() Config {
	return Config{}
}
