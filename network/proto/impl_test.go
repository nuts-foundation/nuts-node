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

	instance.Configure(p2p.NewInterface(), dag.NewMockDAG(mockCtrl), publisher,
		dag.NewMockPayloadStore(mockCtrl), dag.NewMockTransactionSignatureVerifier(mockCtrl), time.Second*2, "local")
	instance.Start()
	instance.Stop()
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
