package network

import (
	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-node/network/protocol"
	"github.com/nuts-foundation/nuts-node/network/protocol/types"
	"github.com/stretchr/testify/assert"
	"testing"
)


func Test_simpleConnectionManager_Connect(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	p := protocol.NewMockProtocol(ctrl)
	cm := newConnectionManager(p)

	const expectedAddress = "foobar:1111"
	p.EXPECT().Connect(expectedAddress)
	cm.Connect(expectedAddress)
}

func Test_simpleConnectionManager_Peers(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	p := protocol.NewMockProtocol(ctrl)
	cm := newConnectionManager(p)

	expectedPeers := []types.Peer{{
		ID:      "1",
		Address: "foobar",
	}}
	p.EXPECT().Peers().Return(expectedPeers)
	assert.Equal(t, expectedPeers, cm.Peers())
}
