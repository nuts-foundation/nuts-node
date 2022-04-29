package jsonld

const moduleName = "JSONLD"

// Config holds the config for the vcr engine
type Config struct {
	// strictMode is a copy from the core server config
	strictMode bool
	// JSONLDContext contains the configuration for the JSON-LD Contexts
	Contexts ContextsConfig `koanf:"jsonld.contexts"`
}

// DefaultConfig returns a fresh Config filled with default values
func DefaultConfig() Config {
	return Config{
		Contexts: DefaultContextConfig(),
	}
}
