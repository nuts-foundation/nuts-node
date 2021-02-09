package auth

// Config holds all the configuration params
type Config struct {
	PublicURL          string     `koanf:"publicUrl"`
	Irma               IrmaConfig `koanf:"irma"`
	ContractValidators []string   `koanf:"contractValidators"`
}

// IrmaConfig holds IRMA configuration params
type IrmaConfig struct {
	SchemeManager     string `koanf:"schemeManager"`
	AutoUpdateSchemas bool   `koanf:"autoUpdateSchemas"`
}

// DefaultConfig returns an instance of Config with the default values.
func DefaultConfig() Config {
	return Config{
		Irma: IrmaConfig{
			SchemeManager:     "pbdf",
			AutoUpdateSchemas: true,
		},
		ContractValidators: []string{"irma", "uzi", "dummy"},
	}
}
