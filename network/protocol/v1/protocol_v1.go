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

// NewProtocolV1 returns a new instance of the protocol v1 implementation.
func NewProtocolV1(config Config, adapterConfig p2p.AdapterConfig) protocol.Protocol {
	return &protocolV1{
		config:        config,
		adapterConfig: adapterConfig,
		online:        adapterConfig.Valid,
		adapter:       p2p.NewAdapter(),
		protocol:      proto.NewProtocol(),
	}
}

type protocolV1 struct {
	config        Config
	adapter       p2p.Adapter
	protocol      proto.Protocol
	adapterConfig p2p.AdapterConfig
	online        bool
}

func (p protocolV1) Configure(graph dag.DAG, publisher dag.Publisher, payloadStore dag.PayloadStore, diagnosticsProvider func() types.Diagnostics) error {
	p.protocol.Configure(p.adapter, graph, publisher, payloadStore, diagnosticsProvider,
		time.Duration(p.config.AdvertHashesInterval)*time.Millisecond,
		time.Duration(p.config.AdvertDiagnosticsInterval)*time.Millisecond,
		time.Duration(p.config.CollectMissingPayloadsInterval)*time.Millisecond,
		p.adapterConfig.PeerID)
	if p.online {
		return p.adapter.Configure(p.adapterConfig)
	}
	return nil
}

func (p protocolV1) Start() error {
	// It's possible that the Nuts node isn't bootstrapped (e.g. TLS configuration incomplete) but that shouldn't
	// prevent it from starting. In that case the network will be in 'offline mode', meaning it can be read from
	// and written to, but it will not try to connect to other peers.
	if p.online {
		if err := p.adapter.Start(); err != nil {
			return err
		}
	} else {
		log.Logger().Warn("Network protocol v1 is in offline mode.")
	}
	p.protocol.Start()
	return nil
}

func (p protocolV1) Stop() error {
	p.protocol.Stop()
	if p.online {
		return p.adapter.Stop()
	}
	return nil
}

func (p protocolV1) Diagnostics() []core.DiagnosticResult {
	return append(p.protocol.Diagnostics(), p.adapter.Diagnostics()...)
}

func (p protocolV1) PeerDiagnostics() map[types.PeerID]types.Diagnostics {
	return p.protocol.PeerDiagnostics()
}

func (p protocolV1) Connect(peerAddress string) {
	_ = p.adapter.ConnectToPeer(peerAddress)
}

func (p protocolV1) Peers() []types.Peer {
	return p.adapter.Peers()
}
