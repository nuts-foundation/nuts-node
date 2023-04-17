package config

// Config specifies the config structure for the crl/certificate blacklist module
type Config struct {
	// URL specifies the URL where the certificate blacklist is downloaded
	URL string `koanf:"url"`

	// TrustedSigner specifies the PEM Ed25519 public key which must sign the blacklist
	TrustedSigner string `koanf:"trustedsigner"`

	// MaxUpdateFailHours specifies the maximum number of hours that a blacklist update can fail
	MaxUpdateFailHours int `koanf:"maxupdatefailhours"`
}
