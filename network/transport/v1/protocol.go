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
	"context"
	"time"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/nuts-foundation/nuts-node/network/transport/grpc"
	"github.com/nuts-foundation/nuts-node/network/transport/v1/logic"
	"github.com/nuts-foundation/nuts-node/network/transport/v1/protobuf"
	grpcLib "google.golang.org/grpc"
)

var _ grpc.Protocol = (*protocolV1)(nil)

// Config specifies config for protocol v1
type Config struct {
	// AdvertHashesInterval specifies how often (in milliseconds) the node should broadcast its last hashes,
	// so other nodes can compare and synchronize.
	AdvertHashesInterval int `koanf:"adverthashesinterval"`
	// AdvertDiagnosticsInterval specifies how often (in milliseconds) the node should query its peers for diagnostic information.
	AdvertDiagnosticsInterval int `koanf:"advertdiagnosticsinterval"`
	// CollectMissingPayloadsInterval specifies how often (in milliseconds) the node should query peers for missing payloads.
	CollectMissingPayloadsInterval int `koanf:"collectmissingpayloadsinterval"`
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
func New(config Config, state dag.State, diagnosticsProvider func() transport.Diagnostics) transport.Protocol {
	result := &protocolV1{
		config: config,
	}
	result.protocol = logic.NewProtocol(result, &result.connectionList, state, diagnosticsProvider)
	return result
}

type protocolV1 struct {
	config         Config
	protocol       logic.Protocol
	connectionList delegatingConnectionList
}

func (p protocolV1) MethodName() string {
	return grpc.GetStreamMethod(protobuf.Network_ServiceDesc.ServiceName, protobuf.Network_ServiceDesc.Streams[0])
}

func (p protocolV1) CreateClientStream(outgoingContext context.Context, grpcConn grpcLib.ClientConnInterface) (grpcLib.ClientStream, error) {
	client := protobuf.NewNetworkClient(grpcConn)
	return client.Connect(outgoingContext)
}

func (p *protocolV1) Register(registrar grpcLib.ServiceRegistrar, acceptor func(stream grpcLib.ServerStream) error, connectionList grpc.ConnectionList, _ transport.ConnectionManager) {
	protobuf.RegisterNetworkServer(registrar, &protocolServer{acceptor: acceptor})
	p.connectionList.target = connectionList
}

func (p protocolV1) CreateEnvelope() interface{} {
	return &protobuf.NetworkMessage{}
}

func (p protocolV1) UnwrapMessage(raw interface{}) interface{} {
	return raw.(*protobuf.NetworkMessage).Message
}

func (p protocolV1) Configure(peerID transport.PeerID) error {
	p.protocol.Configure(
		time.Duration(p.config.AdvertHashesInterval)*time.Millisecond,
		time.Duration(p.config.AdvertDiagnosticsInterval)*time.Millisecond,
		time.Duration(p.config.CollectMissingPayloadsInterval)*time.Millisecond,
		peerID)

	return nil
}

func (p protocolV1) Start() error {
	p.protocol.Start()
	return nil
}

func (p protocolV1) Stop() {
	p.protocol.Stop()
}

func (p protocolV1) Diagnostics() []core.DiagnosticResult {
	return p.protocol.Diagnostics()
}

func (p protocolV1) PeerDiagnostics() map[transport.PeerID]transport.Diagnostics {
	return p.protocol.PeerDiagnostics()
}

func (p protocolV1) Handle(peer transport.Peer, envelope interface{}) error {
	return p.protocol.Handle(peer, envelope)
}

func (p *protocolV1) Send(peer transport.PeerID, envelope *protobuf.NetworkMessage) {
	connection := p.connectionList.Get(grpc.ByPeerID(peer))
	if connection != nil {
		err := connection.Send(p, envelope)
		if err != nil {
			log.Logger().Warnf("Error while sending message (peer=%s): %v", connection.Peer(), err)
		}
	}
}

func (p *protocolV1) Broadcast(envelope *protobuf.NetworkMessage) {
	for _, connection := range p.connectionList.All() {
		if connection.IsConnected() {
			err := connection.Send(p, envelope)
			if err != nil {
				log.Logger().Warnf("Error while broadcasting (peer=%s): %v", connection.Peer(), err)
			}
		}
	}
}

type protocolServer struct {
	acceptor func(grpcLib.ServerStream) error
}

func (p protocolServer) Connect(server protobuf.Network_ConnectServer) error {
	return p.acceptor(server)
}

// delegatingConnectionList delegates ConnectionList calls to another implementation. Temp fix until v1/logic package is refactored into v1.
type delegatingConnectionList struct {
	target grpc.ConnectionList
}

func (d delegatingConnectionList) Get(query ...grpc.Predicate) grpc.Connection {
	return d.target.Get(query...)
}

func (d delegatingConnectionList) All() []grpc.Connection {
	return d.target.All()
}
