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
	v2 "github.com/nuts-foundation/nuts-node/network/transport/v2"
)

// Config holds the config for Transactions
type Config struct {
	// Socket address for gRPC to listen on
	GrpcAddr string `koanf:"network.grpcaddr"`
	// EnableTLS specifies whether to enable TLS for incoming connections.
	EnableTLS bool `koanf:"network.enabletls"`
	// Public address of this nodes other nodes can use to connect to this node.
	BootstrapNodes []string `koanf:"network.bootstrapnodes"`
	// Protocols is the list of network protocols to enable on the server. They are specified by version (v1, v2).
	Protocols   []int  `koanf:"network.protocols"`
	CertFile    string `koanf:"network.certfile"`
	CertKeyFile string `koanf:"network.certkeyfile"`
	// EnableDiscovery tells the node to automatically connect to other nodes
	EnableDiscovery bool   `koanf:"network.enablediscovery"`
	TrustStoreFile  string `koanf:"network.truststorefile"`

	// MaxCRLValidityDays defines the number of days a CRL can be outdated, after that it will hard-fail
	MaxCRLValidityDays int `koanf:"network.maxcrlvaliditydays"`

	// DisableNodeAuthentication allows for bypassing node DID authentication on connections.
	// The SAN from a client certificate is used for this, in development/test certificates might not be availabe.
	// Can't be set to true in strictmode.
	DisableNodeAuthentication bool `koanf:"network.disablenodeauthentication"`

	// NodeDID defines the DID of the organization that operates this node, typically a vendor for EPD software.
	// It is used to identify it on the network.
	NodeDID string `koanf:"network.nodedid"`

	// ProtocolV1 specifies config for protocol v1
	ProtocolV1 v1.Config `koanf:"network.v1"`

	// ProtocolV2 specifies config for protocol v2
	ProtocolV2 v2.Config `koanf:"network.v2"`
}

// IsProtocolEnabled returns true if the protocol is enabled, otherwise false.
func (c Config) IsProtocolEnabled(version int) bool {
	if len(c.Protocols) == 0 {
		return true
	}
	for _, curr := range c.Protocols {
		if curr == version {
			return true
		}
	}
	return false
}

// DefaultConfig returns the default NetworkEngine configuration.
func DefaultConfig() Config {
	return Config{
		GrpcAddr:        ":5555",
		EnableTLS:       true,
		ProtocolV1:      v1.DefaultConfig(),
		ProtocolV2:      v2.DefaultConfig(),
		EnableDiscovery: true,
	}
}
