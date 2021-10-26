package net

import (
	"github.com/nuts-foundation/nuts-node/network/protocol/types"
)

// ConnectionManager manages the connections to peers, making outbound connections if required. It also determines the network layout.
type ConnectionManager interface {
	// Connect attempts to make an outbound connection to the given peer if it's not already connected.
	Connect(peerAddress string)

	// Peers returns a slice containing the peers that are currently connected.
	Peers() []types.Peer

	// Start instructs the ConnectionManager to start accepting connections and prepare to make outbound connections.
	Start() error

	// Stop shuts down the connections made by the ConnectionManager.
	Stop()
}
