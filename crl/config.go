package crl

// Config specifies the config structure for the crl/certificate blacklist module
type Config struct {
	// BlacklistURL specifies the URL where the certificate blacklist is downloaded
	BlacklistURL string `koanf:"blacklisturl"`

	// BlacklistTrustedSigner specifies the PEM Ed25519 public key which must sign the blacklist
	BlacklistTrustedSigner string `koanf:"blacklisttrustedsigner"`

	// MaxUpdateFailHours specifies the maximum number of hours that a blacklist/CRL update can fail
	MaxUpdateFailHours int `koanf:"maxupdatefailhours"`
}

// DefaultConfig provides a default configuration for the certificate blacklisting feature
func DefaultConfig() Config {
	return Config{
		// By default log error messages when a CRL or blacklist is more than 4 hours out of date
		MaxUpdateFailHours: 4,

		// TODO: Use a default certificate blacklist distributed by the nuts foundation. This can be disabled
		// by simply setting an empty string value here, or replaced with a different URL. If updating the URL
		// then a new public key should be placed in the trusted signer field as well.
		BlacklistURL:           "",
		BlacklistTrustedSigner: "",
	}
}
