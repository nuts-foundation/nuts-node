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
	v2 "github.com/nuts-foundation/nuts-node/network/transport/v2"
	"time"
)

// Config holds the config for Transactions
type Config struct {
	// Socket address for gRPC to listen on
	GrpcAddr string `koanf:"network.grpcaddr"`
	// ConnectionTimeout specifies the timeout before an outbound connection attempt times out (in milliseconds).
	ConnectionTimeout int `koanf:"network.connectiontimeout"`
	// MaxBackoff specifies the maximum backoff for outbound connections
	MaxBackoff time.Duration `koanf:"network.maxbackoff"`
	// EnableTLS specifies whether to enable TLS for incoming connections.
	EnableTLS bool      `koanf:"network.enabletls"`
	TLS       TLSConfig `koanf:"network.tls"`
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

	// ProtocolV2 specifies config for protocol v2
	ProtocolV2 v2.Config `koanf:"network.v2"`
}

// TLSConfig specifies how TLS should be configured for network connections.
// For v5, network.enabletls, network.truststorefile, network.certfile and network.certkeyfile must be moved to this struct.
type TLSConfig struct {
	// Offload specifies the TLS offloading mode for incoming/outgoing traffic.
	Offload TLSOffloadingMode `koanf:"offload"`
	// ClientCertHeaderName specifies the name of the HTTP header in which the TLS offloader puts the client certificate in.
	// It is required when TLS offloading for incoming traffic is enabled. The client certificate must be in PEM format.
	ClientCertHeaderName string `koanf:"certheader"`
}

// TLSOffloadingMode defines configurable modes for TLS offloading.
type TLSOffloadingMode string

const (
	// NoOffloading specifies that TLS is not offloaded,
	// meaning incoming and outgoing TLS traffic is terminated at the local node, and not by a proxy inbetween.
	NoOffloading TLSOffloadingMode = ""
	// OffloadIncomingTLS specifies that incoming TLS traffic should be offloaded.
	// It will assume there is a reverse proxy at which TLS is terminated,
	// and which puts the client certificate in PEM format in a configured header.
	OffloadIncomingTLS = "incoming"
)

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
		GrpcAddr:          ":5555",
		ConnectionTimeout: 5000,
		MaxBackoff:        24 * time.Hour,
		EnableTLS:         true,
		ProtocolV2:        v2.DefaultConfig(),
		EnableDiscovery:   true,
	}
}
