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

package v2

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/sirupsen/logrus"
	grpcLib "google.golang.org/grpc"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/events"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/nuts-foundation/nuts-node/network/transport/grpc"
	vdr "github.com/nuts-foundation/nuts-node/vdr/types"
)

var _ grpc.Protocol = (*protocol)(nil)

// Config specifies config for protocol v2
type Config struct {
	// NATS configuration for the replay DAG publisher
	Nats NatsConfig `koanf:"nats"`
}

// NatsConfig holds all NATS related configuration
type NatsConfig struct {
	Port     int    `koanf:"port"`
	Hostname string `koanf:"hostname"`
	Timeout  int    `koanf:"timeout"`
}

// DefaultConfig returns the default config for protocol v2
func DefaultConfig() Config {
	return Config{
		Nats: NatsConfig{
			Port:     4222,
			Hostname: "localhost",
			Timeout:  30,
		},
	}
}

// New creates an instance of the v2 protocol.
func New(config Config, nodeDIDResolver transport.NodeDIDResolver, graph dag.DAG, payloadStore dag.PayloadStore, docResolver vdr.DocResolver, decrypter crypto.Decrypter) transport.Protocol {
	return &protocol{
		config:             config,
		graph:              graph,
		nodeDIDResolver:    nodeDIDResolver,
		payloadStore:       payloadStore,
		decrypter:          decrypter,
		docResolver:        docResolver,
		natsConnectHandler: events.Connect,
	}
}

type protocol struct {
	cancel             func()
	ctx                context.Context
	config             Config
	nodeDIDResolver    transport.NodeDIDResolver
	graph              dag.DAG
	payloadStore       dag.PayloadStore
	decrypter          crypto.Decrypter
	docResolver        vdr.DocResolver
	natsConnectHandler events.ConnectFunc
	connectionList     grpc.ConnectionList
	connectionManager  transport.ConnectionManager
}

func (p protocol) CreateClientStream(outgoingContext context.Context, grpcConn *grpcLib.ClientConn) (grpcLib.ClientStream, error) {
	return NewProtocolClient(grpcConn).Stream(outgoingContext)
}

func (p *protocol) Register(registrar grpcLib.ServiceRegistrar, acceptor func(stream grpcLib.ServerStream) error, connectionList grpc.ConnectionList, connectionManager transport.ConnectionManager) {
	RegisterProtocolServer(registrar, &protocolServer{acceptor: acceptor})
	p.connectionList = connectionList
	p.connectionManager = connectionManager
}

func (p protocol) MethodName() string {
	return grpc.GetStreamMethod(Protocol_ServiceDesc.ServiceName, Protocol_ServiceDesc.Streams[0])
}

func (p protocol) CreateEnvelope() interface{} {
	return &Envelope{}
}

func (p protocol) UnwrapMessage(envelope interface{}) interface{} {
	return envelope.(*Envelope).Message
}

func (p protocol) Configure(_ transport.PeerID) {
}

func (p *protocol) setupNatsHandler() error {
	conn, err := p.natsConnectHandler(
		p.config.Nats.Hostname,
		p.config.Nats.Port,
		time.Duration(p.config.Nats.Timeout)*time.Second,
	)
	if err != nil {
		return err
	}

	js, err := conn.JetStream()
	if err != nil {
		return err
	}

	if _, err = js.Subscribe(events.PrivateTransactionsSubject, func(msg *nats.Msg) {
		if err := p.handlePrivateTx(msg); err != nil {
			logrus.Errorf("failed to handle private transaction: %v", err)

			if err := msg.Nak(); err != nil {
				logrus.Errorf("failed to NACK private transaction event: %v", err)
			}

			return
		}

		if err := msg.Ack(); err != nil {
			logrus.Errorf("failed to ACK private transaction event: %v", err)
		}
	}); err != nil {
		conn.Close()
		return err
	}

	go func() {
		<-p.ctx.Done()
		conn.Close()
	}()

	return nil
}

func (p *protocol) Start() {
	p.ctx, p.cancel = context.WithCancel(context.Background())

	go func() {
		for {
			if err := p.setupNatsHandler(); err != nil {
				logrus.Errorf("failed to setup NATS handler: %v", err)

				select {
				case <-p.ctx.Done():
					return
				case <-time.After(5 * time.Second):
					continue
				}
			}

			return
		}
	}()
}

func (p *protocol) handlePrivateTx(msg *nats.Msg) error {
	nodeDID, err := p.nodeDIDResolver.Resolve()
	if err != nil {
		return err
	}

	if nodeDID.Empty() {
		return errors.New("node DID is not set")
	}

	doc, _, err := p.docResolver.Resolve(nodeDID, nil)
	if err != nil {
		return err
	}

	keyAgreementIDs := make([]string, len(doc.KeyAgreement))

	for i, keyAgreement := range doc.KeyAgreement {
		keyAgreementIDs[i] = keyAgreement.ID.String()
	}

	tx, err := dag.ParseTransaction(msg.Data)
	if err != nil {
		return err
	}

	if len(tx.PAL()) == 0 {
		return errors.New("PAL header is empty")
	}

	epal := dag.EncryptedPAL(tx.PAL())

	pal, err := epal.Decrypt(keyAgreementIDs, p.decrypter)
	if err != nil {
		return err
	}

	// We weren't able to decrypt the PAL, so it wasn't meant for us
	if pal == nil {
		return nil
	}

	fmt.Println(pal)

	return nil
}

func (p *protocol) Stop() {
	if p.cancel != nil {
		p.cancel()
	}
}

func (p protocol) Diagnostics() []core.DiagnosticResult {
	return nil
}

func (p protocol) PeerDiagnostics() map[transport.PeerID]transport.Diagnostics {
	return make(map[transport.PeerID]transport.Diagnostics)
}

func (p *protocol) send(peer transport.Peer, message isEnvelope_Message) error {
	connection := p.connectionList.Get(grpc.ByPeerID(peer.ID))
	if connection == nil {
		return fmt.Errorf("unable to send message, connection not found (peer=%s)", peer)
	}
	return connection.Send(p, &Envelope{Message: message})
}

type protocolServer struct {
	acceptor func(grpcLib.ServerStream) error
}

func (p protocolServer) Stream(server Protocol_StreamServer) error {
	return p.acceptor(server)
}
