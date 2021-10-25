package network

import v1 "github.com/nuts-foundation/nuts-node/network/protocol/v1"

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

	// MaxCRLValidityDays defines the number of days a CRL can be outdated, after that it will hard-fail
	MaxCRLValidityDays int `koanf:"network.maxcrlvaliditydays"`

	// ProtocolV1 specifies config for protocol v1
	ProtocolV1 v1.Config `koanf:"network.v1"`
}

// DefaultConfig returns the default NetworkEngine configuration.
func DefaultConfig() Config {
	return Config{
		GrpcAddr:   ":5555",
		EnableTLS:  true,
		ProtocolV1: v1.DefaultConfig(),
	}
}
