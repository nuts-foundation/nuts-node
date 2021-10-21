package p2p

import (
	"github.com/magiconair/properties/assert"
	"github.com/nuts-foundation/nuts-node/network/protocol/types"
	"testing"
)

func Test_NumberOfPeersStatistic(t *testing.T) {
	statistic := numberOfPeersStatistic{numberOfPeers: 10}
	assert.Equal(t, statistic.String(), "10")
	assert.Equal(t, statistic.Name(), "[P2P Network] Connected peers #")
}

func Test_PeersStatistic(t *testing.T) {
	statistic := peersStatistic{peers: []types.Peer{
		{ID: "abc", Address: "localhost:8080"},
		{ID: "def", Address: "remote:8081"},
	}}
	assert.Equal(t, statistic.String(), "def@remote:8081 abc@localhost:8080")
	assert.Equal(t, statistic.Name(), "[P2P Network] Connected peers")
}

func Test_OwnPeerIDStatistic(t *testing.T) {
	statistic := ownPeerIDStatistic{peerID: "bla"}
	assert.Equal(t, statistic.String(), "bla")
	assert.Equal(t, statistic.Name(), "[P2P Network] Peer ID of local node")
}
