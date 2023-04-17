package config

// Config specifies the config structure for the crl/certificate blacklist module
type Config struct {
	// MaxUpdateFailHours specifies the maximum number of hours that a CRL update can fail
	MaxUpdateFailHours int `koanf:"maxupdatefailhours"`
}
