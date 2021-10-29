package auth

// Config holds all the configuration params
type Config struct {
	IrmaSchemeManager     string   `koanf:"auth.irma.schememanager"`
	IrmaAutoUpdateSchemas bool     `koanf:"auth.irma.autoupdateschemas"`
	HTTPTimeout           int      `koanf:"auth.http.timeout"`
	PublicURL             string   `koanf:"auth.publicurl"`
	ClockSkew             int      `koanf:"auth.clockskew"`
	ContractValidators    []string `koanf:"auth.contractvalidators"`
	CertFile              string   `koanf:"network.certfile"`
	CertKeyFile           string   `koanf:"network.certkeyfile"`
	TrustStoreFile        string   `koanf:"network.truststorefile"`
	MaxCRLValidityDays    int      `koanf:"network.maxcrlvaliditydays"`
}

// DefaultConfig returns an instance of Config with the default values.
func DefaultConfig() Config {
	return Config{
		IrmaSchemeManager:     "pbdf",
		IrmaAutoUpdateSchemas: true,
		HTTPTimeout:           30,
		ClockSkew:             5000,
		ContractValidators:    []string{"irma", "uzi", "dummy"},
	}
}

func (c Config) tlsEnabled() bool {
	return c.CertFile != "" || c.CertKeyFile != ""
}
