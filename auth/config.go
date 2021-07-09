package auth

// Config holds all the configuration params
type Config struct {
	Irma               IrmaConfig `koanf:"irma"`
	HTTP               HTTPConfig `koanf:"http"`
	PublicURL          string     `koanf:"publicurl"`
	ContractValidators []string   `koanf:"contractvalidators"`
}

// IrmaConfig holds IRMA configuration params
type IrmaConfig struct {
	SchemeManager     string `koanf:"schememanager"`
	AutoUpdateSchemas bool   `koanf:"autoupdateschemas"`
}

// HTTPConfig holds HTTP configuration params
type HTTPConfig struct {
	Timeout int `koanf:"timeout"`
}

// DefaultConfig returns an instance of Config with the default values.
func DefaultConfig() Config {
	return Config{
		Irma: IrmaConfig{
			SchemeManager:     "pbdf",
			AutoUpdateSchemas: true,
		},
		HTTP:               HTTPConfig{Timeout: 30},
		ContractValidators: []string{"irma", "uzi", "dummy"},
	}
}
