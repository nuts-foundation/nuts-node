package core

import (
	"github.com/knadh/koanf"
	"github.com/spf13/pflag"
	"strings"
	"time"
)

const defaultClientTimeout = 10 * time.Second
const clientTimeoutFlag = "timeout"

// ClientConfig has CLI client settings.
type ClientConfig struct {
	Address   string        `koanf:"address"`
	Verbosity string        `koanf:"verbosity"`
	Timeout   time.Duration `koanf:"timeout"`
	configMap *koanf.Koanf
}

// NewClientConfig creates a new CLI client config with default values set.
func NewClientConfig() *ClientConfig {
	return &ClientConfig{
		configMap: koanf.New(defaultDelimiter),
		Address:   defaultAddress,
		Verbosity: defaultLogLevel,
		Timeout:   defaultClientTimeout,
	}
}

// Load loads the client config from environment variables and commandline params.
func (cfg *ClientConfig) Load() error {
	return loadConfigIntoStruct(cfg.FlagSet(), cfg, koanf.New(defaultDelimiter))
}

// FlagSet returns the flags for configuring the client config.
func (cfg *ClientConfig) FlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("client", pflag.ContinueOnError)
	flagSet.String(addressFlag, defaultAddress, "Address of the remote node. Must contain at least host and port, URL scheme may be omitted. In that case it 'http://' is prepended.")
	flagSet.Duration(clientTimeoutFlag, defaultClientTimeout, "Client time-out when performing remote operations.")
	return flagSet
}

// GetAddress normalizes and gets the address of the remote server
func (cfg ClientConfig) GetAddress() string {
	addr := cfg.Address
	if !strings.HasPrefix(addr, "http") {
		addr = "http://" + addr
	}
	return addr
}
