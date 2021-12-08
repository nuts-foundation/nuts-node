/*
 * Copyright (C) 2021 Nuts community
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

package network

import (
	"github.com/nuts-foundation/nuts-node/network/transport/v1"
)

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

	// NodeDID defines the DID of the organization that operates this node, typically a vendor for EPD software.
	// It is used to identify it on the network.
	NodeDID string `koanf:"network.nodedid"`

	// NATS configuration for the replay DAG publisher
	Nats NatsConfig `koanf:"network.nats"`

	// ProtocolV1 specifies config for protocol v1
	ProtocolV1 v1.Config `koanf:"network.v1"`
}

// NatsConfig holds all NATS related configuration
type NatsConfig struct {
	Port     int    `koanf:"network.nats.port"`
	Hostname string `koanf:"network.nats.hostname"`
	Timeout  int    `koanf:"network.nats.timeout"`
}

// DefaultConfig returns the default NetworkEngine configuration.
func DefaultConfig() Config {
	return Config{
		GrpcAddr:   ":5555",
		ProtocolV1: v1.DefaultConfig(),
		EnableTLS:  true,
		Nats: NatsConfig{
			Timeout:  30,
			Port:     4022,
			Hostname: "localhost",
		},
	}
}
