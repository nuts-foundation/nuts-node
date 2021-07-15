package auth

// Config holds all the configuration params
type Config struct {
	IrmaSchemeManager     string   `koanf:"auth.irma.schememanager"`
	IrmaAutoUpdateSchemas bool     `koanf:"auth.irma.autoupdateschemas"`
	HTTPTimeout           int      `koanf:"auth.http.timeout"`
	PublicURL             string   `koanf:"auth.publicurl"`
	ContractValidators    []string `koanf:"auth.contractvalidators"`
}

// DefaultConfig returns an instance of Config with the default values.
func DefaultConfig() Config {
	return Config{
		IrmaSchemeManager:     "pbdf",
		IrmaAutoUpdateSchemas: true,
		HTTPTimeout:           30,
		ContractValidators:    []string{"irma", "uzi", "dummy"},
	}
}
