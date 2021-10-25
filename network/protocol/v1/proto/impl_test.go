package proto

import (
	"errors"
	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/network/protocol/types"
	"github.com/nuts-foundation/nuts-node/network/protocol/v1/p2p"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func Test_ProtocolLifecycle(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	publisher := dag.NewMockPublisher(mockCtrl)
	publisher.EXPECT().Subscribe("*", gomock.Any())

	instance := NewProtocol(p2p.NewAdapter(), dag.NewMockDAG(mockCtrl), publisher, dag.NewMockPayloadStore(mockCtrl), nil, )
	instance.Configure(time.Second*2, time.Second*5, 10*time.Second, "local")
	instance.Start()
	instance.Stop()
}

func Test_Protocol_PeerDiagnostics(t *testing.T) {
	instance := NewProtocol(nil, nil, nil, nil, nil).(*protocol)

	instance.peerDiagnostics[peer] = types.Diagnostics{
		Peers:           []types.PeerID{"some-peer"},
		SoftwareVersion: "1.0",
	}
	diagnostics := instance.PeerDiagnostics()
	instance.peerDiagnostics[peer].Peers[0] = "other-peer" // mutate entry to make sure function returns a copy
	assert.Len(t, diagnostics, 1)
	actual := diagnostics[peer]
	assert.Equal(t, "1.0", actual.SoftwareVersion)
	assert.Equal(t, []types.PeerID{"some-peer"}, actual.Peers)
}

func Test_Protocol_StartAdvertingDiagnostics(t *testing.T) {
	t.Run("disabled", func(t *testing.T) {
		instance := NewProtocol(nil, nil, nil, nil, nil).(*protocol)
		instance.advertDiagnosticsInterval = 0 * time.Second // this is what would be configured
		instance.startAdvertingDiagnostics()
		// This is a blocking function when the feature is enabled, so if we reach the end of the test everything works as intended.
	})
}

func Test_Protocol_Diagnostics(t *testing.T) {
	t.Run("peer diagnostics", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		payloadCollector := NewMockmissingPayloadCollector(ctrl)
		payloadCollector.EXPECT().findMissingPayloads().AnyTimes().Return(nil, nil)

		instance := NewProtocol(nil, nil, nil, nil, nil).(*protocol)
		instance.missingPayloadCollector = payloadCollector
		instance.peerOmnihashChannel = make(chan PeerOmnihash, 1)
		peerConnected := make(chan types.Peer, 1)
		peerDisconnected := make(chan types.Peer, 1)

		stats := instance.Diagnostics()[0].(peerOmnihashStatistic)
		assert.Empty(t, stats.peerHashes)

		// Peer connects
		peerConnected <- types.Peer{ID: peer}
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
		peerDisconnected <- types.Peer{ID: peer}
		instance.updateDiagnostics(peerConnected, peerDisconnected)
		stats = instance.Diagnostics()[0].(peerOmnihashStatistic)
		assert.Empty(t, stats.peerHashes)
	})

	t.Run("ok - missing payloads", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		payloadCollector := NewMockmissingPayloadCollector(ctrl)
		payloadCollector.EXPECT().findMissingPayloads().Return([]hash.SHA256Hash{{1}}, nil)

		instance := NewProtocol(nil, nil, nil, nil, nil).(*protocol)
		instance.missingPayloadCollector = payloadCollector
		diagnostics := instance.Diagnostics()
		assert.Equal(t, "[Protocol] Missing Payload Hashes", diagnostics[1].Name())
		assert.Equal(t, "[0100000000000000000000000000000000000000000000000000000000000000]", diagnostics[1].String())
	})

	t.Run("error - missing payloads (doesn't panic/fail)", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		payloadCollector := NewMockmissingPayloadCollector(ctrl)
		payloadCollector.EXPECT().findMissingPayloads().Return(nil, errors.New("oops"))

		instance := NewProtocol(nil, nil, nil, nil, nil).(*protocol)
		instance.missingPayloadCollector = payloadCollector
		diagnostics := instance.Diagnostics()
		assert.Equal(t, "[Protocol] Missing Payload Hashes", diagnostics[1].Name())
		assert.Empty(t, "", diagnostics[1].String())
	})
}
