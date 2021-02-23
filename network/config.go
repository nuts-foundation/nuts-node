package network

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
)

// Config holds the config for Transactions
type Config struct {
	// Socket address for gRPC to listen on
	GrpcAddr string `koanf:"grpcAddr"`
	// EnableTLS specifies whether to enable TLS for incoming connections.
	EnableTLS bool `koanf:"enableTLS"`
	// Public address of this nodes other nodes can use to connect to this node.
	PublicAddr     string   `koanf:"publicAddr"`
	BootstrapNodes []string `koanf:"bootstrapNodes"`
	CertFile       string   `koanf:"certFile"`
	CertKeyFile    string   `koanf:"certKeyFile"`
	TrustStoreFile string   `koanf:"trustStoreFile"`

	// AdvertHashesInterval specifies how often (in milliseconds) the node should broadcasts its last hashes so
	// other nodes can compare and synchronize.
	AdvertHashesInterval int
}

// DefaultConfig returns the default NetworkEngine configuration.
func DefaultConfig() Config {
	return Config{
		GrpcAddr:             ":5555",
		EnableTLS:            true,
		AdvertHashesInterval: 2000,
	}
}

func (c Config) loadTrustStore() (*x509.CertPool, error) {
	trustStore := x509.NewCertPool()
	data, err := ioutil.ReadFile(c.TrustStoreFile)
	if err != nil {
		return nil, fmt.Errorf("unable to read trust store (file=%s): %w", c.TrustStoreFile, err)
	}
	if ok := trustStore.AppendCertsFromPEM(data); !ok {
		return nil, fmt.Errorf("unable to load one or more certificates from trust store (file=%s)", c.TrustStoreFile)
	}
	return trustStore, nil
}
