package protocol

import (
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/network/protocol/types"
)

type Protocol interface {
	// Configure configures the Protocol implementation.
	Configure(graph dag.DAG, publisher dag.Publisher, payloadStore dag.PayloadStore, diagnosticsProvider func() types.Diagnostics) error
	// Start starts the Protocol implementation.
	Start() error
	// Stop stops the Protocol implementation.
	Stop() error
	// Diagnostics collects and returns diagnostical information on the protocol.
	Diagnostics() []core.DiagnosticResult
	// PeerDiagnostics collects and returns diagnostical information on the peers the protocol is communicating with.
	PeerDiagnostics() map[types.PeerID]types.Diagnostics

	// Connect attempts to make an outbound connection to the given peer if it's not already connected.
	// TODO: After refactoring ManagedConnection, this function moves to NetworkManager
	Connect(peerAddress string)

	// Peers returns a slice containing the peers that are currently connected.
	// TODO: After refactoring ManagedConnection, this function moves to NetworkManager
	Peers() []types.Peer
}
