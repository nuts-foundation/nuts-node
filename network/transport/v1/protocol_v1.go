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

package v1

import (
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/nuts-foundation/nuts-node/network/transport/grpc"
	"github.com/nuts-foundation/nuts-node/network/transport/v1/logic"
	"github.com/nuts-foundation/nuts-node/network/transport/v1/p2p"
	grpcLib "google.golang.org/grpc"
	"time"
)

// Config specifies config for protocol v1
type Config struct {
	// AdvertHashesInterval specifies how often (in milliseconds) the node should broadcasts its last hashes,
	// so other nodes can compare and synchronize.
	AdvertHashesInterval int `koanf:"network.v1.adverthashesinterval"`
	// AdvertDiagnosticsInterval specifies how often (in milliseconds) the node should query its peers for diagnostic information.
	AdvertDiagnosticsInterval int `koanf:"network.v1.advertdiagnosticsinterval"`
	// CollectMissingPayloadsInterval specifies how often (in milliseconds) the node should query peers for missing payloads.
	CollectMissingPayloadsInterval int `koanf:"network.v1.collectmissingpayloadsinterval"`
}

// DefaultConfig returns the default configuration for protocol v1.
func DefaultConfig() Config {
	return Config{
		AdvertHashesInterval:           2000,
		AdvertDiagnosticsInterval:      5000,
		CollectMissingPayloadsInterval: 60000,
	}
}

// New returns a new instance of the protocol v1 implementation.
func New(config Config, adapterConfig p2p.AdapterConfig, graph dag.DAG, publisher dag.Publisher, payloadStore dag.PayloadStore, diagnosticsProvider func() transport.Diagnostics) transport.Protocol {
	adapter := p2p.NewAdapter()
	return &protocolV1{
		config:        config,
		adapterConfig: adapterConfig,
		adapter:       adapter,
		protocol:      logic.NewProtocol(adapter, graph, publisher, payloadStore, diagnosticsProvider),
	}
}

type protocolV1 struct {
	config        Config
	adapter       p2p.Adapter
	protocol      logic.Protocol
	adapterConfig p2p.AdapterConfig
}

func (p protocolV1) Configure() error {
	p.protocol.Configure(
		time.Duration(p.config.AdvertHashesInterval)*time.Millisecond,
		time.Duration(p.config.AdvertDiagnosticsInterval)*time.Millisecond,
		time.Duration(p.config.CollectMissingPayloadsInterval)*time.Millisecond,
		p.adapterConfig.PeerID)
	return p.adapter.Configure(p.adapterConfig)
}

func (p protocolV1) Start() error {
	if err := p.adapter.Start(); err != nil {
		return err
	}
	p.protocol.Start()
	return nil
}

func (p protocolV1) Stop() error {
	p.protocol.Stop()
	return p.adapter.Stop()
}

func (p protocolV1) Diagnostics() []core.DiagnosticResult {
	return append(p.protocol.Diagnostics(), p.adapter.Diagnostics()...)
}

func (p protocolV1) PeerDiagnostics() map[transport.PeerID]transport.Diagnostics {
	return p.protocol.PeerDiagnostics()
}

func (p protocolV1) Connect(peerAddress string) {
	_ = p.adapter.ConnectToPeer(peerAddress)
}

func (p protocolV1) Peers() []transport.Peer {
	return p.adapter.Peers()
}

func (p protocolV1) RegisterService(registrar grpcLib.ServiceRegistrar, acceptor grpc.StreamAcceptor) {
	p.adapter.RegisterService(registrar, acceptor)
}
