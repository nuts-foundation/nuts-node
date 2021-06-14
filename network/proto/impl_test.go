package proto

import (
	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/network/p2p"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func Test_ProtocolLifecycle(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()
	instance := NewProtocol()

	publisher := dag.NewMockPublisher(mockCtrl)
	publisher.EXPECT().Subscribe("*", gomock.Any())

	instance.Configure(p2p.NewAdapter(), dag.NewMockDAG(mockCtrl), publisher, dag.NewMockPayloadStore(mockCtrl), nil, time.Second*2, time.Second*5, "local")
	instance.Start()
	instance.Stop()
}

func Test_Protocol_PeerDiagnostics(t *testing.T) {
	instance := NewProtocol().(*protocol)

	instance.peerDiagnostics[peer] = Diagnostics{
		Peers:           []p2p.PeerID{"some-peer"},
		SoftwareVersion: "1.0",
	}
	diagnostics := instance.PeerDiagnostics()
	instance.peerDiagnostics[peer].Peers[0] = "other-peer" // mutate entry to make sure function returns a copy
	assert.Len(t, diagnostics, 1)
	actual := diagnostics[peer]
	assert.Equal(t, "1.0", actual.SoftwareVersion)
	assert.Equal(t, []p2p.PeerID{"some-peer"}, actual.Peers)
}

func Test_Protocol_StartAdvertingDiagnostics(t *testing.T) {
	t.Run("disabled", func(t *testing.T) {
		instance := NewProtocol().(*protocol)
		instance.advertDiagnosticsInterval = 0 * time.Second // this is what would be configured
		instance.startAdvertingDiagnostics()
		// This is a blocking function when the feature is enabled, so if we reach the end of the test everything works as intended.
	})
}

func Test_Protocol_Diagnostics(t *testing.T) {
	instance := NewProtocol().(*protocol)

	instance.peerOmnihashChannel = make(chan PeerOmnihash, 1)
	peerConnected := make(chan p2p.Peer, 1)
	peerDisconnected := make(chan p2p.Peer, 1)

	stats := instance.Diagnostics()[0].(peerOmnihashStatistic)
	assert.Empty(t, stats.peerHashes)

	// Peer connects
	peerConnected <- p2p.Peer{ID: peer}
	instance.updateDiagnostics(peerConnected, peerDisconnected)
	stats = instance.Diagnostics()[0].(peerOmnihashStatistic)
	assert.Len(t, stats.peerHashes, 1)

	// Peer broadcasts hash
	peerHash := hash.SHA256Sum([]byte("Hello, World!"))
	instance.peerOmnihashChannel <- PeerOmnihash{Peer: peer, Hash: peerHash}
	instance.updateDiagnostics(peerConnected, peerDisconnected)
	stats = instance.Diagnostics()[0].(peerOmnihashStatistic)
	assert.Len(t, stats.peerHashes, 1)
	assert.Equal(t, peerHash, stats.peerHashes[peer])

	// Peer disconnects
	peerDisconnected <- p2p.Peer{ID: peer}
	instance.updateDiagnostics(peerConnected, peerDisconnected)
	stats = instance.Diagnostics()[0].(peerOmnihashStatistic)
	assert.Empty(t, stats.peerHashes)
}
