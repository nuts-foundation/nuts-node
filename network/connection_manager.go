package network

import (
	"github.com/nuts-foundation/nuts-node/network/protocol"
	"github.com/nuts-foundation/nuts-node/network/protocol/types"
)

// ConnectionManager manages the connections to peers, making outbound connections if required. It also determines the network layout.
type ConnectionManager interface {
	// Connect attempts to make an outbound connection to the given peer if it's not already connected.
	Connect(peerAddress string)

	// Peers returns a slice containing the peers that are currently connected.
	Peers() []types.Peer
}

// newConnectionManager creates a new ConnectionManager that accepts/creates connections which communicate using the given protocols.
func newConnectionManager(protocols ...protocol.Protocol) ConnectionManager {
	if len(protocols) > 1 {
		// TODO: Support multiple protocol versions
		panic("ConnectionManager: multiple protocols currently not supported")
	}
	return &simpleConnectionManager{protocol: protocols[0]}
}

// simpleConnectionManager is a ConnectionManager that does not discover peers on its own, but just connects to the peers for which Connect() is called.
type simpleConnectionManager struct {
	protocol protocol.Protocol
}

func (s simpleConnectionManager) Connect(peerAddress string) {
	s.protocol.Connect(peerAddress)
}

func (s simpleConnectionManager) Peers() []types.Peer {
	return s.protocol.Peers()
}
