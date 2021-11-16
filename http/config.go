package http

// DefaultConfig returns the default configuration for the HTTP engine.
func DefaultConfig() Config {
	return Config{
		InterfaceConfig: InterfaceConfig{
			Address: ":1323",
		},
		AltBinds: map[string]InterfaceConfig{},
	}
}

// Config is the top-level config struct for HTTP interfaces.
type Config struct {
	// InterfaceConfig contains the config for the default HTTP interface.
	InterfaceConfig `koanf:"default"`
	// AltBinds contains binds for alternative HTTP interfaces. The key of the map is the first part of the path
	// of the URL (e.g. `/internal/some-api` -> `internal`), the value is the HTTP interface it must be bound to.
	AltBinds map[string]InterfaceConfig `koanf:"alt"`
}

// InterfaceConfig contains configuration for an HTTP interface, e.g. address.
// It will probably contain security related properties in the future (TLS configuration, user/pwd requirements).
type InterfaceConfig struct {
	// Address holds the interface address the HTTP service must be bound to, in the format of `interface:port` (e.g. localhost:5555).
	Address string `koanf:"address"`
	// CORS holds the configuration for Cross Origin Resource Sharing.
	CORS CORSConfig `koanf:"cors"`
	// Auth specifies what authentication is required when accessing this interface.
	Auth AuthConfig `koanf:"auth"`
	// TLSMode specifies whether TLS is enabled for this interface, and which flavor.
	TLSMode TLSMode `koanf:"tls"`
}

// TLSMode defines the values for TLS modes
type TLSMode string

const (
	// DisabledHTTPTLSMode specifies that TLS is not enabled for this interface.
	DisabledHTTPTLSMode TLSMode = "disabled"
	// TLSServerCertMode specifies that TLS is enabled for this interface, but no client certificate is required.
	TLSServerCertMode TLSMode = "server"
	// TLServerClientCertMode specifies that TLS is enabled for this interface, and that it will require a client certificate.
	TLServerClientCertMode TLSMode = "server-client"
)

// AuthType defines the type for authentication types constants.
type AuthType string

const (
	// NoAuth specifies that no authentication is required.
	NoAuth AuthType = "no"
	// BearerTokenAuth specifies that a bearer token is required.
	BearerTokenAuth AuthType = "token"
)

// AuthConfig contains the configuration for authentication for an HTTP interface.
type AuthConfig struct {
	// Type specifies the type of authentication required for the interface.
	Type AuthType `koanf:"type"`
}

// CORSConfig contains configuration for Cross Origin Resource Sharing.
type CORSConfig struct {
	// Origin specifies the AllowOrigin option. If no origins are given CORS is considered to be disabled.
	Origin []string `koanf:"origin"`
}

// Enabled returns whether CORS is enabled according to this configuration.
func (cors CORSConfig) Enabled() bool {
	return len(cors.Origin) > 0
}
