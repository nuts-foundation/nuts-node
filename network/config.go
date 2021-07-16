package network

// Config holds the config for Transactions
type Config struct {
	// Socket address for gRPC to listen on
	GrpcAddr string `koanf:"network.grpcaddr"`
	// EnableTLS specifies whether to enable TLS for incoming connections.
	EnableTLS bool `koanf:"network.enabletls"`
	// Public address of this nodes other nodes can use to connect to this node.
	BootstrapNodes []string `koanf:"network.bootstrapnodes"`
	CertFile       string   `koanf:"network.certfile"`
	CertKeyFile    string   `koanf:"network.certkeyfile"`
	TrustStoreFile string   `koanf:"network.truststorefile"`

	// AdvertHashesInterval specifies how often (in milliseconds) the node should broadcasts its last hashes,
	// so other nodes can compare and synchronize.
	AdvertHashesInterval int `koanf:"network.adverthashesinterval"`
	// AdvertDiagnosticsInterval specifies how often (in milliseconds) the node should query its peers for diagnostic information.
	AdvertDiagnosticsInterval int `koanf:"network.advertdiagnosticsinterval"`
}

// DefaultConfig returns the default NetworkEngine configuration.
func DefaultConfig() Config {
	return Config{
		GrpcAddr:                  ":5555",
		EnableTLS:                 true,
		AdvertHashesInterval:      2000,
		AdvertDiagnosticsInterval: 5000,
	}
}
