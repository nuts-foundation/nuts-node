package events

// Config holds all the configuration params
type Config struct {
	Port       int    `koanf:"events.nats.port"`
	Hostname   string `koanf:"events.nats.hostname"`
	StorageDir string `koanf:"events.storagedir"`
}

// DefaultConfig returns an instance of Config with the default values.
func DefaultConfig() Config {
	return Config{
		Port:     4022,
		Hostname: "localhost",
	}
}
