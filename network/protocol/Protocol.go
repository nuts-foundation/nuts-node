package protocol

import (
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/network/protocol/types"
)

type Protocol interface {
	Configure(graph dag.DAG, publisher dag.Publisher, payloadStore dag.PayloadStore, diagnosticsProvider func() types.Diagnostics, peerID types.PeerID) error
	Start() error
	Stop() error
	Diagnostics() []core.DiagnosticResult
	PeerDiagnostics() map[types.PeerID]types.Diagnostics
}
