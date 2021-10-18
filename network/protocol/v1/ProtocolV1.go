package v1

import (
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/network/protocol"
	"github.com/nuts-foundation/nuts-node/network/protocol/types"
	"github.com/nuts-foundation/nuts-node/network/protocol/v1/p2p"
	"github.com/nuts-foundation/nuts-node/network/protocol/v1/proto"
	"time"
)

// ProtocolV1Config specifies config for protocol v1
type ProtocolV1Config struct {
	// AdvertHashesInterval specifies how often (in milliseconds) the node should broadcasts its last hashes,
	// so other nodes can compare and synchronize.
	AdvertHashesInterval int `koanf:"network.v1.adverthashesinterval"`
	// AdvertDiagnosticsInterval specifies how often (in milliseconds) the node should query its peers for diagnostic information.
	AdvertDiagnosticsInterval int `koanf:"network.v1.advertdiagnosticsinterval"`
	// CollectMissingPayloadsInterval specifies how often (in milliseconds) the node should query peers for missing payloads.
	CollectMissingPayloadsInterval int `koanf:"network.v1.collectmissingpayloadsinterval"`
}

func DefaultConfig() ProtocolV1Config {
	return ProtocolV1Config{
		AdvertHashesInterval:           2000,
		AdvertDiagnosticsInterval:      5000,
		CollectMissingPayloadsInterval: 60000,
	}
}

func NewProtocolV1(config ProtocolV1Config, networkConfig p2p.AdapterConfig) protocol.Protocol {
	return &ProtocolV1{
		config:        config,
		networkConfig: networkConfig,
		adapter:       p2p.NewAdapter(),
		protocol:      proto.NewProtocol(),
	}
}

type ProtocolV1 struct {
	config        ProtocolV1Config
	adapter       p2p.Adapter
	protocol      proto.Protocol
	networkConfig p2p.AdapterConfig
}

func (p ProtocolV1) Configure(graph dag.DAG, publisher dag.Publisher, payloadStore dag.PayloadStore, diagnosticsProvider func() types.Diagnostics, peerID types.PeerID) error {
	p.protocol.Configure(p.adapter, graph, publisher, payloadStore, diagnosticsProvider,
		time.Duration(p.config.AdvertHashesInterval)*time.Millisecond,
		time.Duration(p.config.AdvertDiagnosticsInterval)*time.Millisecond,
		time.Duration(p.config.CollectMissingPayloadsInterval)*time.Millisecond,
		peerID)
	return p.adapter.Configure(p.networkConfig)
}

func (p ProtocolV1) Start() error {
	if p.adapter.Configured() {
		// It's possible that the Nuts node isn't bootstrapped (e.g. TLS configuration incomplete) but that shouldn't
		// prevent it from starting. In that case the network will be in 'offline mode', meaning it can be read from
		// and written to, but it will not try to connect to other peers.
		if err := p.adapter.Start(); err != nil {
			return err
		}
	} else {
		log.Logger().Warn("Network engine is in offline mode (P2P layer not configured).")
	}
	p.protocol.Start()
	return nil
}

func (p ProtocolV1) Stop() error {
	p.protocol.Stop()
	return p.adapter.Stop()
}

func (p ProtocolV1) Diagnostics() []core.DiagnosticResult {
	return append(p.protocol.Diagnostics(), p.adapter.Diagnostics()...)
}

func (p ProtocolV1) PeerDiagnostics() map[types.PeerID]types.Diagnostics {
	return p.protocol.PeerDiagnostics()
}
